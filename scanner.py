import threading, time, datetime, socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, ICMP, sr1, conf
import pandas as pd
from tqdm import tqdm
import dash
from dash import dcc, html
from dash.dependencies import Output, Input
import plotly.graph_objects as go
import networkx as nx
import netifaces

# ----------------------------
# CONFIGURATION
# ----------------------------
SCAN_INTERVAL = 300  # seconds between scans (5 minutes)
max_threads = 200
batch_size = 50
ports_to_scan = range(20, 1025)  # default port range
critical_ports = [22, 23, 3389]

open_ports_data = []
live_hosts = []
data_lock = threading.Lock()

# ----------------------------
# NETWORK DISCOVERY
# ----------------------------
def get_local_subnet():
    gateways = netifaces.gateways()
    iface = None
    try:
        iface = gateways.get('default', {}).get(netifaces.AF_INET, [None, None])[1]
    except Exception:
        iface = None
    # Fallback: pick the first interface with an IPv4 address
    if not iface:
        for candidate in netifaces.interfaces():
            addrs = netifaces.ifaddresses(candidate).get(netifaces.AF_INET)
            if addrs and addrs[0].get('addr') and addrs[0].get('netmask'):
                iface = candidate
                break
    if not iface:
        raise RuntimeError("No active IPv4 interface found. Please specify a network or ensure a default gateway is set.")
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
    ip_parts = list(map(int, ip.split('.')))
    mask_parts = list(map(int, netmask.split('.')))
    network = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
    broadcast = [str(ip_parts[i] | (255-mask_parts[i])) for i in range(4)]
    start_ip = ".".join(network[:-1] + ['1'])
    end_ip = ".".join(broadcast[:-1] + ['254'])
    return start_ip, end_ip

def ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_list = [start_ip]
    while temp != end:
        temp[3] += 1
        for i in (3,2,1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_list.append(".".join(map(str, temp)))
    return ip_list

def icmp_ping(ip):
    pkt = IP(dst=ip)/ICMP()
    resp = sr1(pkt, timeout=0.3, verbose=0)
    return resp is not None

# ----------------------------
# PORT & DEVICE DETECTION
# ----------------------------
def detect_service(port):
    common_services = {20:"FTP",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
                       53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
                       3306:"MySQL",3389:"RDP",5900:"VNC",8080:"HTTP-Proxy"}
    return common_services.get(port,"Other")

def detect_os(resp):
    if resp is None or not resp.haslayer(TCP):
        return "Unknown"
    ttl = None
    try:
        ttl = resp[IP].ttl if resp.haslayer(IP) else None
    except Exception:
        ttl = None
    if ttl <= 64: return "Linux/Unix"
    elif ttl <= 128: return "Windows"
    else: return "Unknown"

def detect_device(ip, ports, os_type):
    ports_set = set(ports)
    if 80 in ports_set or 443 in ports_set:
        return "Router/Server" if os_type=="Linux/Unix" else "Windows PC"
    if 22 in ports_set and os_type=="Linux/Unix": return "Linux PC"
    if 23 in ports_set: return "IoT Device"
    if 515 in ports_set or 631 in ports_set: return "Printer"
    if 3389 in ports_set: return "Windows PC/Server"
    return "Unknown Device"

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"

def scan_port(ip, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=0.3, verbose=0)
    if resp is not None and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
        service = detect_service(port)
        os_type = detect_os(resp)
        hostname = resolve_hostname(ip)
        with data_lock:
            existing_ports = [e["Port"] for e in open_ports_data if e["IP"]==ip]
            device_type = detect_device(ip, existing_ports+[port], os_type)
            open_ports_data.append({"IP": ip, "Hostname": hostname, "Port": port,
                                    "Service": service, "OS": os_type, "Device": device_type})

# ----------------------------
# SCANNING LOOP
# ----------------------------
def start_scan_loop():
    global open_ports_data, live_hosts
    start_ip, end_ip = get_local_subnet()
    while True:
        open_ports_data = []
        live_hosts = []
        print(f"[{datetime.datetime.now()}] Starting network scan ({start_ip} - {end_ip})")
        # ICMP Ping Sweep
        for ip in tqdm(ip_range(start_ip,end_ip),desc="Ping Sweep"):
            if icmp_ping(ip): live_hosts.append(ip)
        if not live_hosts:
            print("No live hosts found.")
        else:
            # Threaded Port Scanning
            tasks=[]
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for i in range(0,len(live_hosts),batch_size):
                    batch=live_hosts[i:i+batch_size]
                    for ip in batch:
                        for port in ports_to_scan:
                            tasks.append(executor.submit(scan_port,ip,port))
                for future in tqdm(tasks,desc="Port Scanning"): future.result()
            # Auto-save report
            with data_lock:
                df=pd.DataFrame(open_ports_data)
            timestamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            df.to_csv(f"network_report_{timestamp}.csv",index=False)
            print(f"[{datetime.datetime.now()}] Scan complete. Report saved as network_report_{timestamp}.csv")
        time.sleep(SCAN_INTERVAL)

# ----------------------------
# DASHBOARD SETUP
# ----------------------------
device_options = ["Router/Server","Windows PC","Linux PC","IoT Device","Printer","Unknown Device"]
service_options = ["HTTP","HTTPS","SSH","RDP","FTP","Telnet","MySQL","VNC","Other"]

app = dash.Dash(__name__)
app.layout = html.Div([
    html.H1("Ultimate Network Discovery Dashboard"),
    html.Div([
        html.Div([html.Label("Select Device Types:"),
                  dcc.Dropdown(id='device-filter',
                               options=[{'label':d,'value':d} for d in device_options],
                               value=device_options,multi=True)
                 ], style={'width':'45%','display':'inline-block'}),
        html.Div([html.Label("Select Services:"),
                  dcc.Dropdown(id='service-filter',
                               options=[{'label':s,'value':s} for s in service_options],
                               value=service_options,multi=True)
                 ], style={'width':'45%','display':'inline-block'})
    ]),
    html.Div(id='metrics-panel', style={'marginTop':20}),
    html.Div(id="critical-alerts", style={"color":"red","font-weight":"bold","margin-top":"10px"}),
    html.Div(id="host-details", style={"border":"1px solid black","padding":"10px","margin-top":"10px"}),
    dcc.Graph(id="live-topology", style={'height':'600px'}),
    html.Button("Export Report CSV", id="export-csv", n_clicks=0),
    dcc.Download(id="download-dataframe-csv"),
    dcc.Interval(id="interval-component", interval=2000, n_intervals=0)
])

# ----------------------------
# DASH CALLBACKS
# ----------------------------
@app.callback(
    Output("live-topology","figure"),
    Output("metrics-panel","children"),
    Input("interval-component","n_intervals"),
    Input("device-filter","value"),
    Input("service-filter","value")
)
def update_topology(n, selected_devices, selected_services):
    if not open_ports_data: return go.Figure(), "No data yet..."
    with data_lock: df = pd.DataFrame(open_ports_data)
    G = nx.Graph()
    if selected_devices: df = df[df['Device'].isin(selected_devices)]
    if selected_services: df = df[df['Service'].isin(selected_services)]
    # Add host nodes
    for ip in df['IP'].unique():
        host_df = df[df['IP']==ip]
        G.add_node(ip, label=host_df['Hostname'].iloc[0], device=host_df['Device'].iloc[0])
    # Add edges between host and a port node (ensure port nodes have attributes)
    for _, row in df.iterrows():
        port_node = f"Port {row['Port']}"
        if port_node not in G:
            G.add_node(port_node, label=port_node, device='Port')
        G.add_edge(row['IP'], port_node, service=row['Service'])
    pos = nx.kamada_kawai_layout(G)
    edge_traces=[]
    service_colors={"HTTP":"blue","HTTPS":"darkblue","SSH":"green","RDP":"red","FTP":"orange","Telnet":"purple","MySQL":"brown","VNC":"pink","Other":"grey"}
    for service,color in service_colors.items():
        x_edges,y_edges=[],[]
        for u,v,d in G.edges(data=True):
            if d.get('service')==service:
                x0,y0=pos[u]; x1,y1=pos[v]; x_edges.extend([x0,x1,None]); y_edges.extend([y0,y1,None])
        edge_traces.append(go.Scatter(x=x_edges, y=y_edges, line=dict(width=2,color=color),
                                      hoverinfo='text',mode='lines',name=service))
    node_x,node_y,node_text,node_color,node_custom_ip=[],[],[],[],[]
    color_map = {"Router/Server":"red","Windows PC":"blue","Linux PC":"green","IoT Device":"orange","Printer":"purple","Unknown Device":"grey"}
    for node in G.nodes():
        x,y=pos[node]; node_x.append(x); node_y.append(y)
        if isinstance(node, str) and node.startswith("Port "):
            node_text.append(G.nodes[node]['label'])
            node_custom_ip.append("")
        else:
            host_df = df[df['IP']==node]
            num_ports=len(host_df)
            os_type = host_df['OS'].iloc[0] if not host_df.empty else "Unknown"
            hostname = host_df['Hostname'].iloc[0] if not host_df.empty else node
            node_text.append(f"{hostname} ({node}) - {G.nodes[node]['device']} - {os_type} - {num_ports} ports")
            node_custom_ip.append(node)
        node_color.append(color_map.get(G.nodes[node]['device'],"grey"))
    node_trace=go.Scatter(x=node_x,y=node_y,mode='markers+text',textposition="top center",
                          hoverinfo='text', text=[G.nodes[n]['label'] for n in G.nodes()],
                          customdata=node_custom_ip,
                          marker=dict(color=node_color,size=20,line_width=2))
    fig=go.Figure(data=edge_traces+[node_trace],
                  layout=go.Layout(title='Ultimate Network Topology',
                                   showlegend=True, hovermode='closest',
                                   margin=dict(b=20,l=5,r=5,t=40)))
    total_hosts=df['IP'].nunique(); total_ports=df['Port'].nunique()
    dev_counts=df.groupby('Device')['IP'].nunique().to_dict()
    serv_counts=df.groupby('Service')['Port'].nunique().to_dict()
    metrics_text=[html.P(f"Total Live Hosts: {total_hosts}"),
                  html.P(f"Total Open Ports: {total_ports}"),
                  html.P(f"Device Counts: {dev_counts}"),
                  html.P(f"Service Counts: {serv_counts}")]
    return fig, metrics_text

@app.callback(
    Output("host-details","children"),
    Output("critical-alerts","children"),
    Input("live-topology","clickData")
)
def _is_valid_ip(text):
    try:
        socket.inet_aton(text)
        return True
    except Exception:
        return False

def show_host_details(clickData):
    if not clickData: return "Click a host node to see details",""
    clicked_ip = clickData["points"][0].get("customdata")
    if not clicked_ip or not _is_valid_ip(clicked_ip):
        return "Click a host node to see details",""
    with data_lock: df=pd.DataFrame(open_ports_data)
    host_df=df[df["IP"]==clicked_ip]
    port_info=[html.Li(f"Port {row['Port']} ({row['Service']})") for _,row in host_df.iterrows()]
    os_type = host_df['OS'].iloc[0] if not host_df.empty else "Unknown"
    device_type = host_df['Device'].iloc[0] if not host_df.empty else "Unknown"
    hostname = host_df['Hostname'].iloc[0] if not host_df.empty else clicked_ip
    details=html.Div([html.H4(f"{hostname} - {device_type}"), html.P(f"OS: {os_type}"), html.Ul(port_info)])
    critical=host_df[host_df['Port'].isin(critical_ports)]
    alerts = html.Div()
    if not critical.empty:
        alerts=html.Div([html.H4("⚠ Critical Ports Detected!"),
                         html.Ul([html.Li(f"{row['Port']} ({row['Service']})") for _,row in critical.iterrows()])],
                        style={"color":"red"})
    return details,alerts

@app.callback(
    Output("download-dataframe-csv","data"),
    Input("export-csv","n_clicks"),
    prevent_initial_call=True
)
def export_csv(n_clicks):
    with data_lock: df=pd.DataFrame(open_ports_data)
    timestamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return dcc.send_data_frame(df.to_csv,f"network_report_{timestamp}.csv",index=False)
