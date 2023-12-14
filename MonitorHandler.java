package org.telcolab.firewall;

import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.host.HostService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.slf4j.Logger;

import java.util.*;

/**
 * Object responsible for monitoring traffic.
 * Author: angelbet4
 */
public class MonitorHandler {

    // Execution cycles
    private int current_time = 0;

    // System variables
    private Logger log;
    private DeviceService deviceService;
    private HostService hostService;

    /*
      Traffic limit for a host in one cycle
      (modify to change the behavior of the firewall)
    */
    public static final int BANDWIDTH = 140;

    /*
      Number of consecutive cycles in which the limit must be exceeded
      (modify to change the behavior of the firewall)
    */
    public static final int NUM_CYCLES = 5;

    /*
      Seconds of ban for the accused host
      (modify to change the behavior of the firewall)
    */
    public static final int BAN_TIME = 10;

    // Map HOST, from MAC address to traffic quantity
    private HashMap<MacAddress, Long[]> traffic = new HashMap<MacAddress, Long[]>();

    // List of MAC addresses of hosts blocked by the Firewall
    private ArrayList<MacAddress> blacklist = new ArrayList<MacAddress>();

    // Constructor for system variables
    public MonitorHandler(Logger log, DeviceService deviceService, HostService hostService) {
        this.log = log;
        this.deviceService = deviceService;
        this.hostService = hostService;
    }

    // Method that monitors all ports of all devices
    public void monitor() {

        // Obtain hosts
        Iterable<Host> hosts = hostService.getHosts();

        // For each host, perform monitoring
        for (Host h : hosts) {

            // Obtain host information, port, and connected device
            DeviceId device = h.location().deviceId();
            PortNumber port = h.location().port();
            MacAddress macAddress = h.mac();

            // If the host is unknown, add it to the list of those already monitored
            if (!traffic.containsKey(macAddress))
                traffic.put(macAddress, new Long[NUM_CYCLES]);

            // Obtain port statistics of the device
            List<PortStatistics> statList = deviceService.getPortStatistics(device);

            // If a port corresponds to a host, monitor the traffic
            for (PortStatistics stat : statList) {
                if (Long.valueOf(stat.port()) == port.toLong()) {
                    Long rate = stat.bytesReceived() / 1024;
                    traffic.get(macAddress)[current_time % NUM_CYCLES] = Long.valueOf(rate);
                    break;
                }
            }

            try {
                // Search for the value of interest in the array of measurements
                int temp = current_time % NUM_CYCLES + 1;
                if (current_time % NUM_CYCLES == NUM_CYCLES - 1)
                    temp = 0;

                // Search for a ban if enough time has passed since the start of execution
                if (current_time > NUM_CYCLES)
                    /*
                      If the cumulative traffic of the last limit.cycles measurements exceeds limit.bandwidth
                      ban the host if it hasn't already been done
                    */
                    if ((traffic.get(macAddress)[current_time % NUM_CYCLES] - traffic.get(macAddress)[temp]) >
                            BANDWIDTH * NUM_CYCLES && !blacklist.contains(macAddress))
                        ban(macAddress);

            } catch (NullPointerException e) {/* Do nothing, everything will be okay next cycle */}
        }
        // Update the console
        updateConsole();

        // Increment the global time
        current_time++;
    }

    // Method that updates the log on the screen
    public void updateConsole() {

        // Log all hosts
        log.info("      Host        || Rate");

        for (Map.Entry<MacAddress, Long[]> entry : traffic.entrySet())
            log.info(String.valueOf(entry.getKey()) + " || " + entry.getValue()[current_time % NUM_CYCLES] + " KB");

        // Log blocked hosts
        if (!blacklist.isEmpty()) {

            log.info("");
            log.warn("---Currently Banned Host---");

            for (MacAddress mac : blacklist)
                log.warn(String.valueOf(mac));
        }
    }

    // Method that adds a host to the blacklist
    public void ban(MacAddress macAddress) {
        blacklist.add(macAddress);
    }

    // Method that removes a host from the blacklist
    public void unban(MacAddress macAddress) {
        blacklist.remove(macAddress);
    }

    // GETTERS

    // Method that returns a list of MAC addresses of blocked hosts
    public ArrayList<MacAddress> getDoS() {
        return blacklist;
    }

    // Method that returns traffic statistics of the desired MAC among the last NUM_CYCLES detected
    public Long getTraffic(MacAddress macAddress, int index) {
        return traffic.get(macAddress)[index];
    }
}
