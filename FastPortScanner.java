import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Queue;

public class FastPortScanner {
  // Ansi Codes 4 ever lol
    private static final String RESET = "\u001B[0m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String RED = "\u001B[31m";
    private static final String PURPLE = "\u001B[35m";
    private static final String BOLD = "\u001B[1m";
    
    private static final Map<Integer, String> SERVICES = Map.ofEntries(
    		Map.entry(21, "ftp"),
            Map.entry(22, "ssh"),
            Map.entry(23, "telnet"),
            Map.entry(25, "smtp"),
            Map.entry(53, "dns"),
            Map.entry(80, "http"),
            Map.entry(110, "pop3"),
            Map.entry(111, "rpcbind"),
            Map.entry(135, "msrpc"),
            Map.entry(139, "netbios"),
            Map.entry(143, "imap"),
            Map.entry(443, "https"),
            Map.entry(445, "microsoft-ds"),
            Map.entry(993, "imaps"),
            Map.entry(995, "pop3s"),
            Map.entry(1723, "pptp"),
            Map.entry(3306, "mysql"),
            Map.entry(3389, "rdp"),
            Map.entry(5432, "postgresql"),
            Map.entry(5900, "vnc"),
            Map.entry(6379, "redis"),
            Map.entry(8080, "http-proxy"),
            Map.entry(8443, "https-alt"),
            Map.entry(27017, "mongodb"),
            Map.entry(20, "ftp-data"),
            Map.entry(69, "tftp"),
            Map.entry(88, "kerberos"),
            Map.entry(123, "ntp"),
            Map.entry(137, "netbios-ns"),
            Map.entry(138, "netbios-dgm"),
            Map.entry(161, "snmp"),
            Map.entry(179, "bgp"),
            Map.entry(194, "irc"),
            Map.entry(389, "ldap"),
            Map.entry(427, "slp"),
            Map.entry(465, "smtps"),
            Map.entry(500, "isakmp"),
            Map.entry(515, "printer"),
            Map.entry(520, "rip"),
            Map.entry(548, "afp"),
            Map.entry(554, "rtsp"),
            Map.entry(587, "smtp-submission"),
            Map.entry(636, "ldaps"),
            Map.entry(989, "ftps-data"),
            Map.entry(990, "ftps"),
            Map.entry(1194, "openvpn"),
            Map.entry(1433, "mssql"),
            Map.entry(1521, "oracle"),
            Map.entry(1900, "upnp"),
            Map.entry(2049, "nfs"),
            Map.entry(2082, "cpanel"),
            Map.entry(2083, "cpanel-ssl"),
            Map.entry(2086, "whm"),
            Map.entry(2087, "whm-ssl"),
            Map.entry(2181, "zookeeper"),
            Map.entry(2483, "oracle-ssl"),
            Map.entry(2484, "oracle-ssl-alt"),
            Map.entry(3000, "dev-server"),
            Map.entry(3001, "dev-server-alt"),
            Map.entry(4444, "metasploit"),
            Map.entry(4567, "sinatra"),
            Map.entry(4848, "glassfish"),
            Map.entry(5000, "flask"),
            Map.entry(5060, "sip"),
            Map.entry(5061, "sips"),
            Map.entry(5601, "kibana"),
            Map.entry(5985, "winrm"),
            Map.entry(5986, "winrm-ssl"),
            Map.entry(6667, "irc-alt"),
            Map.entry(7001, "weblogic"),
            Map.entry(7002, "weblogic-ssl"),
            Map.entry(7443, "oracle-admin"),
            Map.entry(8000, "http-alt"),
            Map.entry(8008, "http-alt2"),
            Map.entry(8009, "ajp13"),
            Map.entry(8081, "http-alt3"),
            Map.entry(8181, "http-alt4"),
            Map.entry(9000, "sonarqube"),
            Map.entry(9042, "cassandra"),
            Map.entry(9090, "prometheus"),
            Map.entry(9092, "kafka"),
            Map.entry(9200, "elasticsearch"),
            Map.entry(9418, "git"),
            Map.entry(10000, "webmin"),
            Map.entry(11211, "memcached"),
            Map.entry(25565, "minecraft")
    );
    
    private static final Map<Integer, String> BANNER_PROBES = Map.ofEntries(
        Map.entry(21, "HELP\r\n"),
        Map.entry(22, "\r\n"),
        Map.entry(23, "\r\n"),
        Map.entry(25, "HELP\r\n"),
        Map.entry(80, "HEAD / HTTP/1.0\r\n\r\n"),
        Map.entry(110, "HELP\r\n"),
        Map.entry(143, "a001 LOGOUT\r\n"),
        Map.entry(443, "HEAD / HTTP/1.0\r\n\r\n"),
        Map.entry(445, "\r\n"),
        Map.entry(993, "a001 LOGOUT\r\n"),
        Map.entry(995, "HELP\r\n"),
        Map.entry(3306, "\r\n"),
        Map.entry(5432, "\r\n"),
        Map.entry(6379, "INFO\r\n"),
        Map.entry(8080, "HEAD / HTTP/1.0\r\n\r\n"),
        Map.entry(8443, "HEAD / HTTP/1.0\r\n\r\n")
    );
    
    private static final Map<String, String> FINGERPRINTS = Map.ofEntries(
        Map.entry("SSH", "ssh"),
        Map.entry("OpenSSH", "ssh"),
        Map.entry("HTTP/1.1", "http"),
        Map.entry("nginx", "http"),
        Map.entry("Apache", "http"),
        Map.entry("MySQL", "mysql"),
        Map.entry("PostgreSQL", "postgresql"),
        Map.entry("Redis", "redis"),
        Map.entry("FTP", "ftp"),
        Map.entry("SMTP", "smtp"),
        Map.entry("POP3", "pop3"),
        Map.entry("IMAP", "imap"),
        Map.entry("220 Welcome", "ftp"),
        Map.entry("220 ESMTP", "smtp"),
        Map.entry("+OK", "pop3"),
        Map.entry("* OK", "imap")
    );
    
    private static final List<Integer> TOP_PORTS = List.of(
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    );
    
    private static final int MAX_CONCURRENT = 2000;
    
    public static void main(String[] args) throws Exception {
        if (args.length > 2) {
            System.out.println("Usage: java FastPortScanner [host] [--top]");
            System.out.println("  --top    : scan only top 25 ports (faster)");
            return;
        }
        
        String host = args.length > 0 ? args[0] : "localhost";
        boolean topOnly = args.length > 1 && args[1].equals("--top");
        
        Map<Integer, String> openPorts = new HashMap<>();
        long startTime = System.currentTimeMillis();
        
        System.out.println(BOLD + CYAN + "╔═════════════════════════════════════════╗" + RESET);
		System.out.println(BOLD + CYAN + "║         FAST PORT SCANNER v2.0          ║" + RESET);
		System.out.println(BOLD + CYAN + "║              " + PURPLE + "By URDev" + CYAN + "                   ║" + RESET);
		System.out.println(BOLD + CYAN + "╚═════════════════════════════════════════╝" + RESET);
		System.out.println();
        
        System.out.println(BOLD + "Target: " + YELLOW + host + RESET);
        System.out.println(BOLD + "Mode: " + (topOnly ? YELLOW + "top 25 ports" : YELLOW + "full scan (1-65535)") + RESET);
        System.out.println(BOLD + "Concurrent connections: " + YELLOW + MAX_CONCURRENT + RESET);
        System.out.println();
        
        List<Integer> portsToScan;
        if (topOnly) {
            portsToScan = TOP_PORTS;
        } else {
            portsToScan = new ArrayList<>();
            for (int i = 1; i <= 65535; i++) {
                portsToScan.add(i);
            }
        }
        
        scanPipeline(host, portsToScan, openPorts);
        
        List<Integer> sortedPorts = new ArrayList<>(openPorts.keySet());
        Collections.sort(sortedPorts);
        
        System.out.println("\n\n" + BOLD + GREEN + "OPEN PORTS FOUND:" + RESET);
        System.out.println(BOLD + "┌────────┬──────────────────┬────────────────────────────────────────────┐" + RESET);
        System.out.println(BOLD + "│ Port   │ Service          │ Banner                                     │" + RESET);
        System.out.println(BOLD + "├────────┼──────────────────┼────────────────────────────────────────────┤" + RESET);
        
        for (int port : sortedPorts) {
            String banner = openPorts.get(port);
            String detectedService = detectService(banner, port);
            String displayBanner = banner;
            if (displayBanner.length() > 39) {
                displayBanner = displayBanner.substring(0, 39) + "...";
            }
            
            String serviceColor = GREEN;
            if (detectedService.equals("filtered")) serviceColor = RED;
            if (detectedService.equals("unknown")) serviceColor = YELLOW;
            
            System.out.printf("│ %-6d │ %s%-16s%s │ %-42s │%n", 
                port, 
                serviceColor, 
                detectedService, 
                RESET, 
                displayBanner);
        }
        
        System.out.println(BOLD + "└────────┴──────────────────┴────────────────────────────────────────────┘" + RESET);
        
        System.out.println("\n" + BOLD + "Summary:" + RESET);
        System.out.println("  " + CYAN + "►" + RESET + " Found " + GREEN + sortedPorts.size() + RESET + " open ports");
        
        long endTime = System.currentTimeMillis();
        double seconds = (endTime - startTime) / 1000.0;
        System.out.println("  " + CYAN + "►" + RESET + " Scan finished in " + YELLOW + String.format("%.1f", seconds) + "s" + RESET);
    }
    
    private static String detectService(String banner, int port) {
        String serviceFromPort = SERVICES.get(port);
        if (serviceFromPort != null && !banner.equals("timeout") && !banner.equals("no banner") && !banner.equals("empty") && !banner.equals("closed")) {
            return serviceFromPort;
        }
        
        for (Map.Entry<String, String> entry : FINGERPRINTS.entrySet()) {
            if (banner.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        
        if (banner.equals("timeout")) {
            return "filtered";
        }
        if (banner.equals("no banner") || banner.equals("empty") || banner.equals("closed")) {
            return "unknown";
        }
        
        return "unknown";
    }
    
    private static void scanPipeline(String host, List<Integer> ports, Map<Integer, String> openPorts) throws Exception {
        Selector connectSelector = Selector.open();
        Selector readSelector = Selector.open();
        Queue<Integer> pendingPorts = new ArrayDeque<>(ports);
        Map<SocketChannel, Integer> activeConnections = new HashMap<>();
        Map<SocketChannel, Long> bannerStartTimes = new HashMap<>();
        Map<SocketChannel, Integer> pendingBanners = new HashMap<>();
        ByteBuffer buffer = ByteBuffer.allocate(512);
        int totalPorts = ports.size();
        int completed = 0;
        int lastProgress = -1;
        
        System.out.println(BOLD + "Scanning..." + RESET);
        
        while (completed < totalPorts) {
            while (activeConnections.size() < MAX_CONCURRENT && !pendingPorts.isEmpty()) {
                int port = pendingPorts.poll();
                try {
                    SocketChannel channel = SocketChannel.open();
                    channel.configureBlocking(false);
                    channel.connect(new InetSocketAddress(host, port));
                    channel.register(connectSelector, SelectionKey.OP_CONNECT, port);
                    activeConnections.put(channel, port);
                } catch (Exception e) {
                    completed++;
                }
            }
            
            if (connectSelector.select(100) > 0) {
                Iterator<SelectionKey> keyIterator = connectSelector.selectedKeys().iterator();
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    keyIterator.remove();
                    
                    if (!key.isConnectable()) continue;
                    
                    SocketChannel channel = (SocketChannel) key.channel();
                    int port = (int) key.attachment();
                    
                    try {
                        if (channel.finishConnect()) {
                            channel.register(readSelector, SelectionKey.OP_READ, port);
                            pendingBanners.put(channel, port);
                            bannerStartTimes.put(channel, System.currentTimeMillis());
                            activeConnections.remove(channel);
                            
                            if (BANNER_PROBES.containsKey(port)) {
                                String probe = BANNER_PROBES.get(port);
                                channel.write(ByteBuffer.wrap(probe.getBytes(StandardCharsets.US_ASCII)));
                            }
                        }
                    } catch (Exception e) {
                        activeConnections.remove(channel);
                        completed++;
                        try { channel.close(); } catch (Exception ignored) {}
                    } finally {
                        key.cancel();
                    }
                }
            }
            
            if (readSelector.select(50) > 0) {
                Iterator<SelectionKey> keyIterator = readSelector.selectedKeys().iterator();
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
                    keyIterator.remove();
                    
                    if (!key.isReadable()) continue;
                    
                    SocketChannel channel = (SocketChannel) key.channel();
                    int port = (int) key.attachment();
                    
                    try {
                        buffer.clear();
                        int bytesRead = channel.read(buffer);
                        
                        if (bytesRead > 0) {
                            buffer.flip();
                            byte[] data = new byte[buffer.limit()];
                            buffer.get(data);
                            String banner = new String(data, StandardCharsets.US_ASCII).trim();
                            banner = banner.replace('\n', ' ').replace('\r', ' ');
                            openPorts.put(port, banner);
                        } else {
                            openPorts.put(port, "empty");
                        }
                    } catch (Exception e) {
                        openPorts.put(port, "closed");
                    } finally {
                        key.cancel();
                        pendingBanners.remove(channel);
                        bannerStartTimes.remove(channel);
                        completed++;
                        try { channel.close(); } catch (Exception ignored) {}
                    }
                }
            }
            
            long now = System.currentTimeMillis();
            Iterator<Map.Entry<SocketChannel, Integer>> it = pendingBanners.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<SocketChannel, Integer> entry = it.next();
                SocketChannel channel = entry.getKey();
                Long startTime = bannerStartTimes.get(channel);
                if (startTime != null && now - startTime > 1000) {
                    openPorts.put(entry.getValue(), "timeout");
                    it.remove();
                    bannerStartTimes.remove(channel);
                    completed++;
                    try { channel.close(); } catch (Exception ignored) {}
                }
            }
            
            int progress = (completed * 100) / totalPorts;
            if (progress != lastProgress) {
                String progressBar = getProgressBar(progress, 30);
                System.out.print("\rProgress: " + progressBar + " " + YELLOW + progress + "%" + RESET + " (" + completed + "/" + totalPorts + ")");
                lastProgress = progress;
            }
        }
        
        connectSelector.close();
        readSelector.close();
        System.out.println();
    }
    
    private static String getProgressBar(int percent, int width) {
        StringBuilder bar = new StringBuilder("[");
        int filled = (percent * width) / 100;
        for (int i = 0; i < width; i++) {
            if (i < filled) {
                bar.append(GREEN + "█" + RESET);
            } else {
                bar.append("░");
            }
        }
        bar.append("]");
        return bar.toString();
    }
}
