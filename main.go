package main

import (
	"fmt"
	"github.com/eilonc-dev/moaa/sysinfo"
    "github.com/eilonc-dev/moaa/netinfo"
)

func main() {
    log.Println("Starting to read system info...")
    printSysInfo()
    log.Println("Starting to read network info...")
    printNetInfo()
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

    // This is getNetworkInfo() equivalent code:
    //   info.IP, ipErr = getIPAddresses()
    //	info.NetworkInterfaces, niErr = getNetworkInterfaces()
    //	info.ConnectionStats = getConnectionStats()
    //	info.NetworkConfig = getNetworkConfig()
    //	info.ActiveConnections = getActiveConnections()
    //	info.NetworkTraffic = getNetworkTraffic()

    // Now you can use the info variable to access the network information.
    fmt.Println("Default Gateway:", info.DefaultGateway)
    fmt.Println("Default Interface:", info.DefaultInterface)
    fmt.Println("Interfaces:")
    for _, iface := range info.Interfaces {
        fmt.Println("\tName:", iface.Name)
        fmt.Println("\tHardware Address:", iface.HardwareAddr)
        fmt.Println("\tFlags:", iface.Flags)
        fmt.Println("\tMTU:", iface.MTU)
        fmt.Println("\tIPv4 Addresses:")
        for _, addr := range iface.IPv4Addresses {
            fmt.Println("\t\tAddress:", addr.Address)
            fmt.Println("\t\tNetmask:", addr.Netmask)
            fmt.Println("\t\tNetwork:", addr.Network)
        }
        fmt.Println("\tIPv6 Addresses:")
        for _, addr := range iface.IPv6Addresses {
            fmt.Println("\t\tAddress:", addr.Address)
            fmt.Println("\t\tNetmask:", addr.Netmask)
            fmt.Println("\t\tNetwork:", addr.Network)
        }
    }
}