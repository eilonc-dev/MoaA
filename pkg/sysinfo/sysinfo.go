// This package is used to get the system information of the host machine.
// It is used to get the OS, Architecture, CPUs, kernel version if applicable, what else a security agent would need?
// system info:
// 1. OS
// 2. Arch
// 3. CPUs
// 4. Kernel version
// 5. Go version
// 6. Hostname
// 7. IP address
// 8. MAC address
// 9. FQDN
// 10. Uptime
// 11. Last boot time
// 12. Processes
// 13. Users
// 14. Logged in users
// 15. System load
// 16. CPU usage
// 17. Memory usage
// 18. Disk usage
// 19. File descriptors
// 20. Platform
// 21. Platform family
// 22. Platform version
// 23. Running containers and images
// 24. Installed packages and dependencies (include versions)

package pkg

import (
	"log"
	"sync"
	"fmt"
	"runtime"
	"time"
	"os"
	"os/exec"
	"strings"
	"strconv"
	"syscall"
	"bufio"
	"io"
	"bytes"
	"net"
	"net/http"
	"encoding/json"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/disk"
)

type SystemInfo struct {
	OS string `json:"os"`
	Arch string `json:"arch"`
	CPUs int `json:"cpus"`
	KernelVersion string `json:"kernel_version"`
	GoVersion string `json:"go_version"`
	Hostname string `json:"hostname"`
	IP string `json:"ip"`
	MAC string `json:"mac"`
	FQDN string `json:"fqdn"`
	Uptime string `json:"uptime"`
	LastBootTime string `json:"last_boot_time"`
	Processes int `json:"processes"`
	Users int `json:"users"`
	LoggedInUsers int `json:"logged_in_users"`
	SystemLoad float64 `json:"system_load"`
	CPUUsage float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage float64 `json:"disk_usage"`
	FileDescriptors int `json:"file_descriptors"`
	Platform string `json:"platform"`
	PlatformFamily string `json:"platform_family"`
	PlatformVersion string `json:"platform_version"`
	RunningContainers []string `json:"running_containers"`
	InstalledPackages []string `json:"installed_packages"`
}

func GetSystemInfo() SystemInfo {
	var systemInfo SystemInfo
	systemInfo.OS = runtime.GOOS
	systemInfo.Arch = runtime.GOARCH
	systemInfo.CPUs = runtime.NumCPU()
	systemInfo.KernelVersion = getKernelVersion()
	systemInfo.GoVersion = runtime.Version()
	systemInfo.Hostname = getHostname()
	systemInfo.IP = getIP()
	systemInfo.MAC = getMAC()
	systemInfo.FQDN = getFQDN()
	systemInfo.Uptime = getUptime()
	systemInfo.LastBootTime = getLastBootTime()
	systemInfo.Processes = getProcesses()
	systemInfo.Users = getUsers()
	systemInfo.LoggedInUsers = getLoggedInUsers()
	systemInfo.SystemLoad = getSystemLoad()
	systemInfo.CPUUsage = getCPUUsage()
	systemInfo.MemoryUsage = getMemoryUsage()
	systemInfo.DiskUsage = getDiskUsage()
	systemInfo.FileDescriptors = getFileDescriptors()
	systemInfo.Platform = getPlatform()
	systemInfo.PlatformFamily = getPlatformFamily()
	systemInfo.PlatformVersion = getPlatformVersion()
	systemInfo.RunningContainers = GetRunningContainers()
	systemInfo.InstalledPackages = getInstalledPackages()
	return systemInfo
}

func CollectSystemInfo() SystemInfo {
    var info SystemInfo

    info.Processes = getProcesses()
    info.Users = getUsers()
    info.LoggedInUsers = getLoggedInUsers()
    info.SystemLoad = getSystemLoad()
    info.CPUUsage = getCPUUsage()
    info.MemoryUsage = getMemoryUsage()
    info.DiskUsage = getDiskUsage()
    info.FileDescriptors = getFileDescriptors()
    info.Platform = getPlatform()
    info.PlatformFamily = getPlatformFamily()
    info.PlatformVersion = getPlatformVersion()
    info.RunningContainers = GetRunningContainers()
	info.InstalledPackages = getInstalledPackages()
    return info
}

func getKernelVersion() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	cmd := exec.Command("uname", "-r")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println("Error getting kernel version:", err)
		return ""
	}
	return strings.TrimSpace(out.String())
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("Error getting hostname:", err)
		return ""
	}
	return hostname
}

func getIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Println("Error getting IP:", err)
		return ""
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			log.Println("Error parsing CIDR:", err)
			continue
		}
		if ip.IsLoopback() {
			continue
		}
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

func getMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Println("Error getting MAC:", err)
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac != "" {
			return mac
		}
	}
	return ""
}

func getFQDN() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	cmd := exec.Command("hostname", "-f")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println("Error getting FQDN:", err)
		return ""
	}
	return strings.TrimSpace(out.String())
}

func getUptime() string {
	uptime, err := host.Uptime()
	if err != nil {
		log.Println("Error getting uptime:", err)
		return ""
	}
	return strconv.FormatFloat(uptime, 'f', 2, 64)
}

func getLastBootTime() string {
	lastBootTime, err := host.BootTime()
	if err != nil {
		log.Println("Error getting last boot time:", err)
		return ""
	}
	return time.Unix(int64(lastBootTime), 0).String()
}

func getProcesses() int {
	processes, err := host.Processes()
	if err != nil {
		log.Println("Error getting processes:", err)
		return 0
	}
	return len(processes)
}

func getUsers() int {
	users, err := host.Users()
	if err != nil {
		log.Println("Error getting users:", err)
		return 0
	}
	return len(users)
}

func getLoggedInUsers() int {
	// linux logged in users
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd := exec.Command("who")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			log.Println("Error getting logged in users:", err)
			return 0
		}
		return strings.Count(out.String(), "\n")
	}
	else if runtime.GOOS == "windows" {
		// windows logged in users
		cmd := exec.Command("query", "user")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			log.Println("Error getting logged in users:", err)
			return 0
		}
	}
	else {
		return 0
	}
}

func getSystemLoad() float64 {
	load, err := host.LoadAvg()
	if err != nil {
		log.Println("Error getting system load:", err)
		return 0
	}
	return load.Load1
}

func getCPUUsage() float64 {
	cpuUsage, err := cpu.Percent(0, false)
	if err != nil {
		log.Println("Error getting CPU usage:", err)
		return 0
	}
	return cpuUsage[0]
}

func getMemoryUsage() float64 {
	memoryUsage, err := mem.VirtualMemory()
	if err != nil {
		log.Println("Error getting memory usage:", err)
		return 0
	}
	return memoryUsage.UsedPercent
}

func getDiskUsage() float64 {
    if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
        partitions, err := disk.Partitions(false)
        if err != nil {
            log.Println("Error getting partitions:", err)
            return 0
        }
        var totalUsedSpace uint64
        var totalSpace uint64
        for _, partition := range partitions {
            diskUsage, err := disk.Usage(partition.Mountpoint)
            if err != nil {
                log.Println("Error getting disk usage for partition", partition.Mountpoint, ":", err)
                continue
            }
            totalUsedSpace += diskUsage.Used
            totalSpace += diskUsage.Total
        }
        if totalSpace == 0 {
            return 0
        }
        return float64(totalUsedSpace) / float64(totalSpace) * 100
    }
	else if runtime.GOOS == "windows" {
		// windows disk usage
        cmd := exec.Command("wmic", "logicaldisk", "get", "freespace,size")
        var out bytes.Buffer
        cmd.Stdout = &out
        err := cmd.Run()
        if err != nil {
            log.Println("Error getting disk usage:", err)
            return 0
        }
        scanner := bufio.NewScanner(strings.NewReader(out.String()))
        scanner.Split(bufio.ScanLines)
        var totalFreeSpace uint64
        var totalSpace uint64
        for scanner.Scan() {
            line := scanner.Text()
            fields := strings.Fields(line)
            if len(fields) != 2 {
                continue
            }
            freeSpace, err := strconv.ParseUint(fields[0], 10, 64)
            if err != nil {
                log.Println("Error parsing free space:", err)
                continue
            }
            totalSpaceOnDisk, err := strconv.ParseUint(fields[1], 10, 64)
            if err != nil {
                log.Println("Error parsing total space:", err)
                continue
            }
            totalFreeSpace += freeSpace
            totalSpace += totalSpaceOnDisk
        }
        if totalSpace == 0 {
            return 0
        }
        return 100 - float64(totalFreeSpace) / float64(totalSpace) * 100
    }
    return 0
}

func getFileDescriptors() int {
	fileDescriptors, err := host.Connections("all")
	if err != nil {
		log.Println("Error getting file descriptors:", err)
		return 0
	}
	return len(fileDescriptors)
}

func getPlatform() string {
	platform, _, _, err := host.PlatformInformation()
	if err != nil {
		log.Println("Error getting platform:", err)
		return ""
	}
	return platform
}

func getPlatformFamily() string {
	_, platformFamily, _, err := host.PlatformInformation()
	if err != nil {
		log.Println("Error getting platform family:", err)
		return ""
	}
	return platformFamily
}

func getPlatformVersion() string {
	_, _, platformVersion, err := host.PlatformInformation()
	if err != nil {
		log.Println("Error getting platform version:", err)
		return ""
	}
	return platformVersion
}

func GetRunningContainers() []string {
    var runningContainers []string

    // Check if Docker is installed and running
    if _, err := exec.LookPath("docker"); err != nil {
        log.Println("Docker is not installed")
        return runningContainers
    }

    cmd := exec.Command("docker", "ps", "-q")
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()

    // Check if the Docker command failed to run
    if err != nil {
        log.Printf("Failed to execute command 'docker ps -q': %v", err)
        return runningContainers
    }

    scanner := bufio.NewScanner(&out)
    for scanner.Scan() {
        runningContainers = append(runningContainers, scanner.Text())
    }

    // Check if the Docker command returned an error status
    if err := scanner.Err(); err != nil {
        log.Printf("Error reading Docker output: %v", err)
    }

    return runningContainers
}

func getInstalledPackages() []string {
	var installedPackages []string
	// like rpm -qa in linux
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd := exec.Command("rpm", "-qa")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			log.Println("Error getting installed packages:", err)
			return installedPackages
		}
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			installedPackages = append(installedPackages, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Println("Error reading rpm output:", err)
		}
	}
	else if runtime.GOOS == "windows" {
		// windows installed packages
		cmd := exec.Command("wmic", "product", "get", "name")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			log.Println("Error getting installed packages:", err)
			return installedPackages
		}
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			installedPackages = append(installedPackages, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Println("Error reading wmic output:", err)
		}
	}
	else {
		return installedPackages
	}
}