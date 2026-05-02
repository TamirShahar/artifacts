#!/usr/bin/env bash
set -euo pipefail

usage() {
		cat <<'EOF'
Usage: $0 <command>

Commands:
	build              Rebuild and start the full compose stack
	stop               Stop all containers
	http_client [N]    Run the HTTP client as `victim_user` in the victim container (N times for loop, default 1)
	ping               Ping example.com as `victim_user` in the victim container
	sniff_victim_all   Sniff all packets on the victim as `root` (numbered)
	sniff_victim_syn   Sniff only SYN packets on the victim as `root` (numbered)
	sniff_victim_dns   Sniff DNS packets on the victim as `root` (numbered)
	sniff_httpserver   Sniff all packets on the HTTP server as `root` (numbered)
	cbpf               Run cbpf_preprocessing as `malicious_user` in the victim container
	ipoptions          Run ipoptions_preprocessing as `malicious_user` in the victim container
	tcp_main_cbpf      Run main attack with CBPF as `malicious_user` in the victim container
	tcp_main_ipoptions Run main attack with IP options as `malicious_user` in the victim container
	capture            Run ISN capture (capture TCP ISNs) in the ARN container
	tcp_inject         Run TCP packet injection by the ARN container
	dns_inject         Run DNS packet injection by the ARN container
	dns_main [N]       Run DNS cache poisoning victim side as `malicious_user` in the victim container (N times for loop, default 1)
	shell_victim1      Open a shell as `victim_user` in the victim container
	shell_victim2      Open a shell as `malicious_user` in the victim container
	shell_arn          Open an interactive shell in the `arn` container
	shell_httpserver   Open an interactive shell in the `httpserver` container
	shell_recursive_resolver Open an interactive shell in the `recursive_resolver` container
	shell_attacker_authoritative_nameserver Open an interactive shell in the `attacker_authoritative_nameserver` container
	shell_real_authoritative_nameserver Open an interactive shell in the `real_authoritative_nameserver` container
	help             Show this message
EOF
}

run_as_user() {
	# $1 = user, $2 = container, $3 = command
	# Print service/container name and the username evaluated inside the container, then run the command
	docker compose exec -u "$1" "$2" sh -lc "echo Container: $2; echo User: \$(whoami); id;  echo '----------------------------------------------------------------------------'; $3"
}
cmd=${1:-help}
case "$cmd" in
	build)
		echo "Rebuilding and starting full stack..."
		docker compose up -d --build
		;;
	stop)
		echo "Force stopping all containers..."
		docker compose kill
		docker compose down --remove-orphans
		;;
	cbpf)
		run_as_user malicious_user victim "/usr/local/bin/cbpf_preprocessing" | tee logs/tcp_hijacking/cbpf_preprocessing.log
		;;

	ipoptions)
		run_as_user malicious_user victim "/usr/local/bin/ipoptions_preprocessing"
		;;

	tcp_main_cbpf)
		run_as_user malicious_user victim "/usr/local/bin/main_tcp cbpf"
		;;

	tcp_main_ipoptions)
		run_as_user malicious_user victim "/usr/local/bin/main_tcp ipoptions"
		;;

	http_client)
		run_as_user victim_user victim "python3 /artifact/tcp_attack/client.py ${2:-}"
		;;

	ping)
		run_as_user victim_user victim "ping -c 4 example.com"
		;;

	sniff_victim_all)
		docker compose exec -u root victim tcpdump -i any -nn -l | tee logs/tcp_hijacking/sniff_victim_all.log | nl -ba
		;;

	sniff_victim_syn)
		docker compose exec -u root victim tcpdump -i any -nn -l "tcp[tcpflags] & tcp-syn != 0 and (tcp[tcpflags] & tcp-ack) == 0" | nl -ba
		;;

	sniff_victim_dns)
		docker compose exec -u root victim tcpdump -i any -nn -l "port 53" | tee logs/dns_cache_poisoning/sniff_victim_dns.log | nl -ba
		;;

	sniff_httpserver)
		docker compose exec -u root httpserver tcpdump -i any -nn -l | nl -ba
		;;

	capture)
		docker compose exec arn sh -c "/usr/local/bin/capture"
		;;

	tcp_inject)
		docker compose exec arn sh -c "/usr/local/bin/attacker"
		;;

	dns_inject)
		docker compose exec arn sh -c "/usr/local/bin/dns_inject"
		;;

	dns_main)
		run_as_user malicious_user victim "/usr/local/bin/dns_main ${2:-}"
		;;

	shell_victim1)
		docker compose exec -u victim_user victim bash
		;;

	shell_victim2)
		docker compose exec -u malicious_user victim bash
		;;

	shell_arn)
		docker compose exec arn bash
		;;

	shell_httpserver)
		docker compose exec httpserver sh
		;;

	shell_recursive_resolver)
		docker compose exec recursive_resolver sh
		;;

	shell_attacker_authoritative_nameserver)
		docker compose exec attacker_authoritative_nameserver sh
		;;

	shell_real_authoritative_nameserver)
		docker compose exec real_authoritative_nameserver sh
		;;

    

	help|*)
		usage
		;;
esac
