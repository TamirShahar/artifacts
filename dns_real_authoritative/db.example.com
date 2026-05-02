$TTL 60
@   IN  SOA ns.example.com. admin.example.com. (
        2026050101 ; serial
        60         ; refresh
        60         ; retry
        604800     ; expire
        60 )       ; minimum

    IN  NS  ns.example.com.
ns  IN  A   192.0.2.200
@   IN  A   192.0.2.124
