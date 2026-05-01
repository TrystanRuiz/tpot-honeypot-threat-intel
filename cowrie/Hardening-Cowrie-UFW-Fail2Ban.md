# Hardening with UFW & Fail2Ban

## UFW

Enabled UFW on the honeypot VM with a default deny on all incoming traffic. Only ports 22 (real SSH for management) and 2222 (Cowrie) are open.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 2222/tcp
sudo ufw enable
```

Everything else gets dropped. If someone tries hitting any other port on this box, it's just gone.

![UFW status](../screenshots/hardening/05-ufw-status.png)

## Blocking a Single IP

To test this out, I SSH'd into the honeypot from Kali (192.168.1.165) first to make sure the connection was working.

![SSH working before block](../screenshots/hardening/06-ssh-before-block.png)

Then on the honeypot, I added a deny rule for that IP. The important thing here is using `ufw insert 1` instead of just `ufw deny`. If you just do `ufw deny`, the allow rules for ports 22 and 2222 get processed first and the traffic goes through anyway. `insert 1` puts the deny rule at the very top so it gets checked before anything else.

```bash
sudo ufw insert 1 deny from 192.168.1.165
sudo ufw status numbered
```

![UFW deny rule inserted at position 1](../screenshots/hardening/07-ufw-deny-ip.png)

Back on Kali, tried running Hydra and SSH again. Both just hang and eventually time out. The IP is completely blocked from reaching the honeypot.

![Kali blocked by UFW](../screenshots/hardening/08-kali-blocked.png)

After confirming it works, I deleted the rule to clean up.

```bash
sudo ufw delete deny from 192.168.1.165
```

![Rule deleted](../screenshots/hardening/09-rule-deleted.png)

## Blocking a Subnet

Instead of blocking one IP at a time, you can block an entire subnet. This is useful if an attacker has multiple machines on the same network or if you want to block a whole range.

```bash
sudo ufw insert 1 deny from 192.168.1.0/24
sudo ufw status numbered
```

This blocks every IP from 192.168.1.1 to 192.168.1.254.

![Subnet block rule](../screenshots/hardening/10-subnet-block.png)

From Kali, SSH hangs again. The entire /24 is blocked.

![Kali blocked by subnet rule](../screenshots/hardening/11-subnet-blocked-kali.png)

Cleaned up the rule after testing.

```bash
sudo ufw delete deny from 192.168.1.0/24
```

![Subnet rule deleted, clean UFW](../screenshots/hardening/12-subnet-deleted.png)

## The Problem

Before fail2ban, Hydra could brute force the honeypot and find passwords without any consequences. It would just keep running through the wordlist until it found matches.

## Fail2Ban Setup

Installed fail2ban on the honeypot VM and created a custom jail for Cowrie. The filter watches Cowrie's log file and matches any login attempt (failed or succeeded) from an IP. If an IP hits 3 login attempts within 60 seconds, it gets banned for 1 hour.

The jail config (`/etc/fail2ban/jail.local`):

```
[cowrie]
enabled = true
filter = cowrie
logpath = /home/cowrie/cowrie/cowrie/var/log/cowrie/cowrie.log
maxretry = 3
findtime = 60
bantime = 3600
port = 2222
```

The filter regex (`/etc/fail2ban/filter.d/cowrie.conf`):

```
[Definition]
failregex = .*\[HoneyPotSSHTransport,\S+,<HOST>\] login attempt .* (failed|succeeded)
```

## Testing It

Ran Hydra again from Kali. It still found 3 passwords but fail2ban caught the login attempts and banned the IP right after.

![Hydra attack after fail2ban](../screenshots/hardening/01-hydra-attack.png)

Checking the cowrie jail on the honeypot shows 192.168.1.194 is now banned. 4 total failed attempts detected, 1 IP currently banned.

![fail2ban showing the ban](../screenshots/hardening/02-fail2ban-banned.png)

## Confirming the Ban

Tried to SSH back into the honeypot from Kali and got `Connection refused`. The IP is completely blocked on port 2222.

![Connection refused from Kali](../screenshots/hardening/03-connection-refused.png)

## Fail2Ban Logs in Splunk

The fail2ban log is also forwarded to Splunk through the Universal Forwarder. You can search `sourcetype="fail2ban"` and see the ban event with the IP and timestamp.

![Splunk showing fail2ban ban event](../screenshots/hardening/04-splunk-fail2ban.png)
