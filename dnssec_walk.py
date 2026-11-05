import dns.resolver
import dns.dnssec
import dns.rdatatype
import dns.name
import argparse

def get_dnssec_records(domain, resolver):
    try:
        # Request DNSKEY with DNSSEC (DO=1 flag)
        response = resolver.resolve(domain, dns.rdatatype.DNSKEY, raise_on_no_answer=False)

        if response.rrset:
            dnskey_records = [r.to_text() for r in response.rrset]
            return dnskey_records
        else:
            return None

    except dns.resolver.NoAnswer:
        print(f"  ⚠ No DNSSEC records found for {domain} (NoAnswer)")
    except dns.resolver.NXDOMAIN:
        print(f"  ❌ Domain does not exist: {domain}")
    except dns.resolver.LifetimeTimeout:
        print(f"  ❌ Timeout retrieving DNSSEC records for {domain}")
    except dns.exception.DNSException as e:
        print(f"  ❌ Unexpected DNS error for {domain}: {e}")

    return None

def validate_dnssec(domain, resolver):
    print(f"\n🔍 Checking DNSSEC for {domain}...")

    dnskey_records = get_dnssec_records(domain, resolver)

    if not dnskey_records:
        print(f"  ❌ No DNSSEC records found for {domain}")
        return False

    print(f"\n✅ DNSSEC Validation Results for {domain}:")
    print("  📜 DNSKEY Records:")
    for record in dnskey_records:
        print(f"    {record}")

    return True

def main():
    parser = argparse.ArgumentParser(description="Validate DNSSEC from domain to root.")
    parser.add_argument("domain", help="The domain name to check")
    parser.add_argument("--timeout", type=int, default=10, help="Set timeout value in seconds (default: 10)")

    args = parser.parse_args()

    # Configure resolver with timeout
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare Public DNS
    resolver.lifetime = args.timeout
    resolver.timeout = args.timeout // 2  # Per-query timeout

    # Validate DNSSEC for the full domain and parent zones
    domain_parts = args.domain.split(".")
    for i in range(len(domain_parts)):
        subdomain = ".".join(domain_parts[i:])
        validate_dnssec(subdomain, resolver)

if __name__ == "__main__":
    main()
