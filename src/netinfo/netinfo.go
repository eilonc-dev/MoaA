// This package is used to get the network information of the host machine.
// It collects the following information:
// - IP:
//     - IPv4 - Private and Public
//     - IPv6 - Private and Public
// - Network Interfaces:
//     - list of all network interfaces
//     - Status of each interface
//     - MAC address of each interface
// - Connection Statistics:
//     - TCP
//     - UDP
//     - ICMP
//     - IP
//     - ports (open and closed)
// - Network Configuration:
//     - DNS
//     - Subnet Mask
//     - Default Gateway
// - Active Connections:
//     - current active connections by protocol
//     - current active connections by port
//     - current active connections by IP
// - Network Traffic:
//     - incoming traffic
//     - outgoing traffic
//     - total traffic


package netinfo

import (
	"net"
	"os"
	"log"
	gopsutilnet "github.com/shirou/gopsutil/net"
	"bufio"
	"strings"
	"strconv"
)

// NetworkInfo is a struct that holds all the network information of the host machine.
type NetworkInfo struct {
	IP                []string
	NetworkInterfaces []NetworkInterface
	ConnectionStats   ConnectionStats
	NetworkConfig     NetworkConfig
	ActiveConnections ActiveConnections
	NetworkTraffic    NetworkTraffic
}

// NetworkInterface is a struct that holds the information of a network interface.
type NetworkInterface struct {
	Name   string
	Status string
	MAC    string
}

// ConnectionStats is a struct that holds the connection statistics of the host machine.
type ConnectionStats struct {
	TCP  TCPStats
	UDP  UDPStats
	ICMP ICMPStats
	IP   IPStats
}

// TCPStats is a struct that holds the TCP connection statistics of the host machine.
type TCPStats struct {
	Established int
	SynSent     int
	SynRecv     int
	FinWait1    int
	FinWait2    int
	TimeWait    int
	Close       int
	CloseWait   int
	LastAck     int
	Listen      int
	Closing     int
}

// UDPStats is a struct that holds the UDP connection statistics of the host machine.
type UDPStats struct {
	Established int
}

// ICMPStats is a struct that holds the ICMP connection statistics of the host machine.
type ICMPStats struct {
	Established int
}

// IPStats is a struct that holds the IP connection statistics of the host machine.
type IPStats struct {
	Established int
}

// NetworkConfig is a struct that holds the network configuration of the host machine.
type NetworkConfig struct {
	DNS            []string
	SubnetMask     string
	DefaultGateway string
}

// ActiveConnections is a struct that holds the active connections of the host machine.
type ActiveConnections struct {
	ByProtocol []Connection
	ByPort     []Connection
	ByIP       []Connection
}

// Connection is a struct that holds the information of a connection.
type Connection struct {
	Protocol string
	Port     string
	IP       string
}

// NetworkTraffic is a struct that holds the network traffic of the host machine.
type NetworkTraffic struct {
	Incoming int
	Outgoing int
	Total    int
}

// GetNetworkInfo is a function that returns the network information of the host machine.
func GetNetworkInfo() NetworkInfo {
	var info NetworkInfo
	info.IP = getIPAddresses()
	info.NetworkInterfaces = getNetworkInterfaces()
	info.ConnectionStats = getConnectionStats()
	info.NetworkConfig = getNetworkConfig()
	info.ActiveConnections = getActiveConnections()
	info.NetworkTraffic = getNetworkTraffic()
	return info
}

// getIPAddresses is a function that returns the IP addresses of the host machine.
func getIPAddresses() ([]string) {
	var ipAddresses []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Println("failed to retrieve IP addresses: %v", err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && !ip.IsLoopback() && ip.To4() != nil {
			ipAddresses = append(ipAddresses, ip.String())
		} // how to handle errors? (if any)
		if err != nil {
			log.Println("failed to retrieve IP addresses: %v", err)
		}
	}
	return ipAddresses
}

// getNetworkInterfaces is a function that returns the network interfaces of the host machine.
func getNetworkInterfaces() ([]NetworkInterface) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Println("failed to retrieve network interfaces: %v", err)
	}

	var networkInterfaces []NetworkInterface
	for _, iface := range interfaces {
		networkInterface := NetworkInterface{
			Name:   iface.Name,
			Status: iface.Flags.String(),
			MAC:    iface.HardwareAddr.String(),
		}
		networkInterfaces = append(networkInterfaces, networkInterface)
	}

	return networkInterfaces
}

// getConnectionStats is a function that returns the connection statistics of the host machine.
func getConnectionStats() ConnectionStats {
	var stats ConnectionStats
	stats.TCP = getTCPStats()
	stats.UDP = getUDPStats()
	stats.ICMP = getICMPStats()
	stats.IP = getIPStats()
	return stats
}

// getTCPStats is a function that returns the TCP connection statistics of the host machine.
func getTCPStats() (TCPStats) {
	var stats TCPStats
	tcp, err := gopsutilnet.Connections("all")
	if err != nil {
		log.Println("Failed to retrieve TCP connection statistics: %v", err)
	}
	for _, t := range tcp {
		switch t.Status {
		case "ESTABLISHED":
			stats.Established++
		case "SYN_SENT":
			stats.SynSent++
		case "SYN_RECV":
			stats.SynRecv++
		case "FIN_WAIT1":
			stats.FinWait1++
		case "FIN_WAIT2":
			stats.FinWait2++
		case "TIME_WAIT":
			stats.TimeWait++
		case "CLOSE":
			stats.Close++
		case "CLOSE_WAIT":
			stats.CloseWait++
		case "LAST_ACK":
			stats.LastAck++
		case "LISTEN":
			stats.Listen++
		case "CLOSING":
			stats.Closing++
		}
	}
	return stats
}

// getUDPStats is a function that returns the UDP connection statistics of the host machine.
func getUDPStats() (UDPStats) {
	var stats UDPStats
	udp, err := gopsutilnet.Connections("udp")
	if err != nil {
		log.Println("Failed to retrieve UDP connection statistics: %v", err)
	}
	for _, u := range udp {
		if u.Status == "ESTABLISHED" {
			stats.Established++
		}
	}
	return stats
}

// getICMPStats is a function that returns the ICMP connection statistics of the host machine.
func getICMPStats() (ICMPStats) {
	var stats ICMPStats
	icmp, err := gopsutilnet.Connections("icmp")
	if err != nil {
		log.Println("Failed to retrieve ICMP connection statistics: %v", err)
	}
	for _, i := range icmp {
		if i.Status == "ESTABLISHED" {
			stats.Established++
		}
	}
	return stats
}

// getIPStats is a function that returns the IP connection statistics of the host machine.
func getIPStats() (IPStats) {
	var stats IPStats
	ip, err := gopsutilnet.Connections("ip")
	if err != nil {
		log.Println("Failed to retrieve IP connection statistics: %v", err)
	}
	for _, i := range ip {
		if i.Status == "ESTABLISHED" {
			stats.Established++
		}
	}
	return stats
}

// getNetworkConfig is a function that returns the network configuration of the host machine.
func getNetworkConfig() NetworkConfig {
	var config NetworkConfig
	config.DNS = getDNS()
	config.SubnetMask = getSubnetMask()
	config.DefaultGateway = getDefaultGateway()
	return config
}

// getDNS is a function that returns the DNS of the host machine.
func getDNS() ([]string) {
	var dns []string
	resolv, err := os.Open("/etc/resolv.conf")
	if err != nil {
		log.Println("Failed to retrieve DNS: %v", err)
	}
	defer resolv.Close()
	scanner := bufio.NewScanner(resolv)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "nameserver") {
			dns = append(dns, strings.Fields(line)[1])
		}
	}
	return dns
}

// getSubnetMask is a function that returns the subnet mask of the host machine.
func getSubnetMask() (string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Println("Failed to retrieve subnet mask: %v", err)
	}
	var subnetMask string
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Println("Failed to retrieve subnet mask: %v", err)
			continue
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), "/") {
				subnetMask = strings.Split(addr.String(), "/")[1]
				return subnetMask
			}
		}
	}
	return ""
}

// getDefaultGateway is a function that returns the default gateway of the host machine.
func getDefaultGateway() (string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Println("Failed to retrieve default gateway: %v", err)
	}
	var defaultGateway string
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Println("Failed to retrieve default gateway: %v", err)
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), "/") {
				defaultGateway = strings.Split(addr.String(), "/")[0]
				return defaultGateway
			}
		}
	}
	return ""
}

// getActiveConnections is a function that returns the active connections of the host machine.
func getActiveConnections() ActiveConnections {
	var connections ActiveConnections
	connections.ByProtocol = getActiveConnectionsByProtocol()
	connections.ByPort = getActiveConnectionsByPort()
	connections.ByIP = getActiveConnectionsByIP()
	return connections
}

// getActiveConnectionsByProtocol is a function that returns the active connections of the host machine by protocol.
func getActiveConnectionsByProtocol() ([]Connection) {
	var connections []Connection
	tcp, err := gopsutilnet.Connections("tcp")
	if err != nil {
		log.Println("Failed to retrieve active connections by protocol: %v", err)
	}
	for _, t := range tcp {
		tPortStr := strconv.FormatUint(uint64(t.Laddr.Port), 10)
		connection := Connection{
			Protocol: "tcp",
			Port:     tPortStr,
			IP:       t.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	udp, err := gopsutilnet.Connections("udp")
	if err != nil {
		log.Println("Failed to retrieve active connections by protocol: %v", err)
	}
	for _, u := range udp {
		uPortStr := strconv.FormatUint(uint64(u.Laddr.Port), 10)
		connection := Connection{
			Protocol: "udp",
			Port:     uPortStr,
			IP:       u.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	icmp, err := gopsutilnet.Connections("icmp")
	if err != nil {
		log.Println("Failed to retrieve active connections by protocol: %v", err)
	}
	for _, i := range icmp {
		iPortStr := strconv.FormatUint(uint64(i.Laddr.Port), 10)
		connection := Connection{
			Protocol: "icmp",
			Port:     iPortStr,
			IP:       i.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	ip, err := gopsutilnet.Connections("ip")
	if err != nil {
		log.Println("Failed to retrieve active connections by protocol: %v", err)
	}
	for _, i := range ip {
		iPortStr := strconv.FormatUint(uint64(i.Laddr.Port), 10)
		connection := Connection{
			Protocol: "ip",
			Port:     iPortStr,
			IP:       i.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	return connections
}

// getActiveConnectionsByPort is a function that returns the active connections of the host machine by port.
func getActiveConnectionsByPort() ([]Connection) {
	var connections []Connection
	tcp, err := gopsutilnet.Connections("tcp")
	if err != nil {
		log.Println("Failed to retrieve active connections by port: %v", err)
	}
	for _, t := range tcp {
		tPortStr := strconv.FormatUint(uint64(t.Laddr.Port), 10)
		connection := Connection{
			Protocol: "tcp",
			Port:     tPortStr,
			IP:       t.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	udp, err := gopsutilnet.Connections("udp")
	if err != nil {
		log.Println("Failed to retrieve active connections by port: %v", err)
	}
	for _, u := range udp {
		uPortStr := strconv.FormatUint(uint64(u.Laddr.Port), 10)
		connection := Connection{
			Protocol: "udp",
			Port:     uPortStr,
			IP:       u.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	return connections
}

// getActiveConnectionsByIP is a function that returns the active connections of the host machine by IP.
func getActiveConnectionsByIP() ([]Connection) {
	var connections []Connection
	tcp, err := gopsutilnet.Connections("tcp")
	if err != nil {
		log.Println("Failed to retrieve active connections by IP: %v", err)
	}
	for _, t := range tcp {
		tPortStr := strconv.FormatUint(uint64(t.Laddr.Port), 10)
		connection := Connection{
			Protocol: "tcp",
			Port:     tPortStr,
			IP:       t.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	udp, err := gopsutilnet.Connections("udp")
	if err != nil {
		log.Println("Failed to retrieve active connections by IP: %v", err)
	}
	for _, u := range udp {
		uPortStr := strconv.FormatUint(uint64(u.Laddr.Port), 10)
		connection := Connection{
			Protocol: "udp",
			Port:     uPortStr,
			IP:       u.Raddr.IP,
		}
		connections = append(connections, connection)
	}
	return connections
}

// getNetworkTraffic is a function that returns the network traffic of the host machine.
func getNetworkTraffic() NetworkTraffic {
	var traffic NetworkTraffic
	traffic.Incoming = getIncomingTraffic()
	traffic.Outgoing = getOutgoingTraffic()
	traffic.Total = getTotalTraffic()
	return traffic
}

// getIncomingTraffic is a function that returns the incoming traffic of the host machine.
func getIncomingTraffic() (int) {
	var incomingTraffic int
	netStats, err := gopsutilnet.IOCounters(false)
	if err != nil {
		log.Println("Failed to retrieve incoming traffic: %v", err)
	}
	for _, netStat := range netStats {
		incomingTraffic += int(netStat.BytesRecv)
	}
	return incomingTraffic
}

// getOutgoingTraffic is a function that returns the outgoing traffic of the host machine.
func getOutgoingTraffic() (int) {
	var outgoingTraffic int
	netStats, err := gopsutilnet.IOCounters(false)
	if err != nil {
		log.Println("Failed to retrieve outgoing traffic: %v", err)
	}
	for _, netStat := range netStats {
		outgoingTraffic += int(netStat.BytesSent)
	}
	return outgoingTraffic
}

// getTotalTraffic is a function that returns the total traffic of the host machine.
func getTotalTraffic() (int) {
	var totalTraffic int
	netStats, err := gopsutilnet.IOCounters(false)
	if err != nil {
		log.Println("Failed to retrieve total traffic: %v", err)
	}
	for _, netStat := range netStats {
		totalTraffic += int(netStat.BytesSent + netStat.BytesRecv)
	}
	return totalTraffic
}