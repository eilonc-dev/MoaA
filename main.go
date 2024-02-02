package main

import (
    "log"
	"fmt"
	"github.com/eilonc-dev/moaa/src/sysinfo"
    "github.com/eilonc-dev/moaa/src/netinfo"
    "go.uber.org/zap"
)

func main() {
    logger, err := zap.NewDevelopment()
    logger, err := zap.NewProduction()
    if err != nil {
      log.Fatalf("can't initialize zap logger: %v", err)
    }
    defer logger.Sync()
    sugar := logger.Sugar()
    logger.Info("Starting to read system info...")
    suger.Infow("Starting to read system info...")
    printSysInfo()
    logger.Info("Finished reading system info")
    logger.Info("Starting to read network info...")
    printNetInfo()
    logger.Info("Finished reading network info")
}

func printSysInfo() {
	info := sysinfo.GetSystemInfo()
    // Now you can use the info variable to access the system information.
    fmt.Println("OS:", info.OS)
    fmt.Println("Architecture:", info.Arch)
    fmt.Println("CPUs:", info.CPUs)
    fmt.Println("Kernel Version:", info.KernelVersion)
    fmt.Println("Go Version:", info.GoVersion)
    fmt.Println("Hostname:", info.Hostname)
    fmt.Println("IP:", info.IP)
    fmt.Println("MAC:", info.MAC)
    fmt.Println("FQDN:", info.FQDN)
    fmt.Println("Uptime:", info.Uptime, "seconds")
    fmt.Println("Last Boot Time:", info.LastBootTime)
    fmt.Println("Processes:", info.Processes)
    fmt.Println("Users:", info.Users)
    fmt.Println("Logged In Users:", info.LoggedInUsers)
    fmt.Println("System Load:", info.SystemLoad)
    fmt.Println("CPU Usage:", info.CPUUsage)
    fmt.Println("Memory Usage:", info.MemoryUsage)
    fmt.Println("Disk Usage:", info.DiskUsage)
    fmt.Println("File Descriptors:", info.FileDescriptors)
    fmt.Println("Platform:", info.Platform)
    fmt.Println("Platform Family:", info.PlatformFamily)
    fmt.Println("Platform Version:", info.PlatformVersion)

    fmt.Println("Running Containers:")
    for _, container := range info.RunningContainers {
        fmt.Println("\t", container)
    }

    fmt.Println("Installed Packages:")
    for _, pkg := range info.InstalledPackages {
        fmt.Println("\t", pkg)
    }
}

func printNetInfo() {
    info := netinfo.GetNetworkInfo()
    fmt.Println("Default Gateway:", info.NetworkConfig.DefaultGateway)
    fmt.Println("Interfaces:")
    for _, iface := range info.NetworkInterfaces {
        fmt.Println("\tName:", iface.Name)
        fmt.Println("\tStatus:", iface.Status)
        fmt.Println("\tMAC:", iface.MAC)
    }
    fmt.Println("Connection Statistics:")
    fmt.Println("\tTCP Established:", info.ConnectionStats.TCP.Established)
    fmt.Println("\tTCP SynSent:", info.ConnectionStats.TCP.SynSent)
    fmt.Println("\tTCP SynRecv:", info.ConnectionStats.TCP.SynRecv)
    fmt.Println("\tTCP FinWait1:", info.ConnectionStats.TCP.FinWait1)
    fmt.Println("\tTCP FinWait2:", info.ConnectionStats.TCP.FinWait2)
    fmt.Println("\tTCP TimeWait:", info.ConnectionStats.TCP.TimeWait)
    fmt.Println("\tTCP Close:", info.ConnectionStats.TCP.Close)
    fmt.Println("\tTCP CloseWait:", info.ConnectionStats.TCP.CloseWait)
    fmt.Println("\tTCP LastAck:", info.ConnectionStats.TCP.LastAck)
    fmt.Println("\tTCP Listen:", info.ConnectionStats.TCP.Listen)
    fmt.Println("\tTCP Closing:", info.ConnectionStats.TCP.Closing)
    fmt.Println("\tUDP Established:", info.ConnectionStats.UDP.Established)
    fmt.Println("\tICMP Established:", info.ConnectionStats.ICMP.Established)
    fmt.Println("\tIP Established:", info.ConnectionStats.IP.Established)
    fmt.Println("Network Configuration:")
    fmt.Println("\tDNS:", info.NetworkConfig.DNS)
    fmt.Println("\tSubnet Mask:", info.NetworkConfig.SubnetMask)
    fmt.Println("Active Connections:")
    for _, conn := range info.ActiveConnections.ByProtocol {
        fmt.Println("\tProtocol:", conn.Protocol)
        fmt.Println("\tPort:", conn.Port)
        fmt.Println("\tIP:", conn.IP)
    }
    fmt.Println("Network Traffic:")
    fmt.Println("\tIncoming:", info.NetworkTraffic.Incoming)
    fmt.Println("\tOutgoing:", info.NetworkTraffic.Outgoing)
    fmt.Println("\tTotal:", info.NetworkTraffic.Total)
}