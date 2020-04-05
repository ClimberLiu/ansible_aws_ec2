# ansible_aws_ec2

## Description
This sample ansible playbook will provision an AWS EC2 instance (with CentOS image by default) with some additional configuration and settings, including:
* apply security group
* apply os hardening and firewall settings
* install docker
* deploy container
* Additional tasks related to that container 
## Requirements
- Ansible role [os-hardening](https://github.com/dev-sec/ansible-os-hardening).
   #### Installation
   ```
   ansible-galaxy install dev-sec.os-hardening
   ```
## The execution result likes below:
```
$ ansible-playbook -i inventory main.yml --vault-password-file ~/vault.pass

PLAY [provisioner] ***************************************************************************************************************************************************************************************************************************

TASK [Create key pair] ***********************************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [Create a security group] ***************************************************************************************************************************************************************************************************************
ok: [localhost]

TASK [Provision instance(s)] *****************************************************************************************************************************************************************************************************************
changed: [localhost]

TASK [Add new instance to host group] ********************************************************************************************************************************************************************************************************
changed: [localhost] => (item={'id': 'i-02ddc97490b0f4042', 'ami_launch_index': '0', 'private_ip': ...

TASK [Wait for SSH to come up] ***************************************************************************************************************************************************************************************************************
ok: [localhost -> ...

PLAY [webservers] ****************************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [Install iptables-services] *************************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Update iptables for port 22, 80, 443] **************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

PLAY [webservers] ****************************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : Set OS family dependent variables] ******************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : Set OS dependent variables] *************************************************************************************************************************************************************************************

TASK [dev-sec.os-hardening : install auditd package | package-08] ****************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : configure auditd | package-08] **********************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : create limits.d-directory if it does not exist | sysctl-31a, sysctl-31b] ****************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : create additional limits config file -> 10.hardcore.conf | sysctl-31a, sysctl-31b] ******************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : set 10.hardcore.conf perms to 0400 and root ownership] **********************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove 10.hardcore.conf config file] ****************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : create login.defs | os-05, os-05b] ******************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : find files with write-permissions for group] ********************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => (item=/usr/local/sbin)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/local/bin)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/sbin)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin)
ok: [xxx.xxx.xxx.xxx] => (item=/sbin)
ok: [xxx.xxx.xxx.xxx] => (item=/bin)

TASK [dev-sec.os-hardening : minimize access on found files] *********************************************************************************************************************************************************************************

TASK [dev-sec.os-hardening : change shadow ownership to root and mode to 0600 | os-02] *******************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : change passwd ownership to root and mode to 0644 | os-03] *******************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : change su-binary to only be accessible to user and group root] **************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : update pam on Debian systems] ***********************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove pam ccreds to disable password caching] ******************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove pam_cracklib, because it does not play nice with passwdqc] ***********************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : install the package for strong password checking] ***************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : configure passwdqc] *********************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove passwdqc] ************************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : install tally2] *************************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : configure tally2] ***********************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : delete tally2 when retries is 0] ********************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove pam_cracklib, because it does not play nice with passwdqc] ***********************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : install the package for strong password checking] ***************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove passwdqc] ************************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : configure passwdqc and tally via central system-auth confic] ****************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : NSA 2.3.3.5 Upgrade Password Hashing Algorithm to SHA-512] ******************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : install modprobe to disable filesystems | os-10] ****************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : check if efi is installed] **************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove vfat from fs-list if efi is used] ************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : disable unused filesystems | os-10] *****************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : add pinerolo_profile.sh to profile.d] ***************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove pinerolo_profile.sh from profile.d] **********************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : create securetty] ***********************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove suid/sgid bit from binaries in blacklist | os-06] ********************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/rcp)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/rlogin)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/rsh)
changed: [xxx.xxx.xxx.xxx] => (item=/usr/libexec/openssh/ssh-keysign)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/lib/openssh/ssh-keysign)
changed: [xxx.xxx.xxx.xxx] => (item=/sbin/netreport)
changed: [xxx.xxx.xxx.xxx] => (item=/usr/sbin/usernetctl)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/sbin/userisdnctl)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/sbin/pppd)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/lockfile)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/mail-lock)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/mail-unlock)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/mail-touchlock)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/dotlockfile)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/arping)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/sbin/uuidd)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/bin/mtr)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/lib/evolution/camel-lock-helper-1.2)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/lib/pt_chown)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/lib/eject/dmcrypt-get-device)
ok: [xxx.xxx.xxx.xxx] => (item=/usr/lib/mc/cons.saver)

TASK [dev-sec.os-hardening : find binaries with suid/sgid set | os-06] ***********************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : gather files from which to remove suids/sgids and remove system white-listed files | os-06] *********************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove suid/sgid bit from all binaries except in system and user whitelist | os-06] *****************************************************************************************************************************

TASK [dev-sec.os-hardening : protect sysctl.conf] ********************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : set Daemon umask, do config for rhel-family | NSA 2.2.4.1] ******************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : install initramfs-tools] ****************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : rebuild initramfs with starting pack of modules, if module loading at runtime is disabled] **********************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : create a combined sysctl-dict if overwrites are defined] ********************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : Change various sysctl-settings, look at the sysctl-vars file for documentation] *********************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.ip_forward', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.all.forwarding', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.all.accept_ra', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.accept_ra', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.rp_filter', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.rp_filter', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.icmp_echo_ignore_broadcasts', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.icmp_ignore_bogus_error_responses', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.icmp_ratelimit', 'value': 100})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.icmp_ratemask', 'value': 88089})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.all.disable_ipv6', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.tcp_timestamps', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.arp_ignore', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.arp_announce', 'value': 2})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.tcp_rfc1337', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.shared_media', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.shared_media', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.accept_source_route', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.accept_source_route', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.accept_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.accept_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.secure_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.secure_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.accept_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.all.accept_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.send_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.send_redirects', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.all.log_martians', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv4.conf.default.log_martians', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.router_solicitations', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.accept_ra_rtr_pref', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.accept_ra_pinfo', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.accept_ra_defrtr', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.autoconf', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.dad_transmits', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'net.ipv6.conf.default.max_addresses', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'kernel.sysrq', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'fs.suid_dumpable', 'value': 0})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'kernel.randomize_va_space', 'value': 2})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'kernel.core_uses_pid', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'kernel.kptr_restrict', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'kernel.yama.ptrace_scope', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'vm.mmap_min_addr', 'value': 65536})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'fs.protected_hardlinks', 'value': 1})
changed: [xxx.xxx.xxx.xxx] => (item={'key': 'fs.protected_symlinks', 'value': 1})

TASK [dev-sec.os-hardening : Change various sysctl-settings on rhel6-hosts or older, look at the sysctl-vars file for documentation] *********************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : Apply ufw defaults] *********************************************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : get UID_MIN from login.defs] ************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : calculate UID_MAX from UID_MIN by substracting 1] ***************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : set UID_MAX on Debian-systems if no login.defs exist] ***********************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : set UID_MAX on other systems if no login.defs exist] ************************************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : get all system accounts] ****************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove always ignored system accounts from list] ****************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : change system accounts not on the user provided ignore-list] ****************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => (item=bin)
ok: [xxx.xxx.xxx.xxx] => (item=daemon)
ok: [xxx.xxx.xxx.xxx] => (item=adm)
ok: [xxx.xxx.xxx.xxx] => (item=lp)
ok: [xxx.xxx.xxx.xxx] => (item=mail)
ok: [xxx.xxx.xxx.xxx] => (item=operator)
ok: [xxx.xxx.xxx.xxx] => (item=games)
ok: [xxx.xxx.xxx.xxx] => (item=ftp)
ok: [xxx.xxx.xxx.xxx] => (item=nobody)
changed: [xxx.xxx.xxx.xxx] => (item=systemd-network)
changed: [xxx.xxx.xxx.xxx] => (item=dbus)
changed: [xxx.xxx.xxx.xxx] => (item=polkitd)
changed: [xxx.xxx.xxx.xxx] => (item=sshd)
changed: [xxx.xxx.xxx.xxx] => (item=chrony)

TASK [dev-sec.os-hardening : Get user accounts | os-09] **************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : delete rhosts-files from system | os-09] ************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => (item=root)
ok: [xxx.xxx.xxx.xxx] => (item=bin)
ok: [xxx.xxx.xxx.xxx] => (item=daemon)
ok: [xxx.xxx.xxx.xxx] => (item=adm)
ok: [xxx.xxx.xxx.xxx] => (item=lp)
ok: [xxx.xxx.xxx.xxx] => (item=sync)
ok: [xxx.xxx.xxx.xxx] => (item=shutdown)
ok: [xxx.xxx.xxx.xxx] => (item=halt)
ok: [xxx.xxx.xxx.xxx] => (item=mail)
ok: [xxx.xxx.xxx.xxx] => (item=operator)
ok: [xxx.xxx.xxx.xxx] => (item=games)
ok: [xxx.xxx.xxx.xxx] => (item=ftp)
ok: [xxx.xxx.xxx.xxx] => (item=nobody)
ok: [xxx.xxx.xxx.xxx] => (item=systemd-network)
ok: [xxx.xxx.xxx.xxx] => (item=dbus)
ok: [xxx.xxx.xxx.xxx] => (item=polkitd)
ok: [xxx.xxx.xxx.xxx] => (item=sshd)
ok: [xxx.xxx.xxx.xxx] => (item=chrony)
ok: [xxx.xxx.xxx.xxx] => (item=centos)

TASK [dev-sec.os-hardening : delete hosts.equiv from system | os-01] *************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : delete .netrc-files from system | os-09] ************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => (item=root)
ok: [xxx.xxx.xxx.xxx] => (item=bin)
ok: [xxx.xxx.xxx.xxx] => (item=daemon)
ok: [xxx.xxx.xxx.xxx] => (item=adm)
ok: [xxx.xxx.xxx.xxx] => (item=lp)
ok: [xxx.xxx.xxx.xxx] => (item=sync)
ok: [xxx.xxx.xxx.xxx] => (item=shutdown)
ok: [xxx.xxx.xxx.xxx] => (item=halt)
ok: [xxx.xxx.xxx.xxx] => (item=mail)
ok: [xxx.xxx.xxx.xxx] => (item=operator)
ok: [xxx.xxx.xxx.xxx] => (item=games)
ok: [xxx.xxx.xxx.xxx] => (item=ftp)
ok: [xxx.xxx.xxx.xxx] => (item=nobody)
ok: [xxx.xxx.xxx.xxx] => (item=systemd-network)
ok: [xxx.xxx.xxx.xxx] => (item=dbus)
ok: [xxx.xxx.xxx.xxx] => (item=polkitd)
ok: [xxx.xxx.xxx.xxx] => (item=sshd)
ok: [xxx.xxx.xxx.xxx] => (item=chrony)
ok: [xxx.xxx.xxx.xxx] => (item=centos)

TASK [dev-sec.os-hardening : remove unused repositories] *************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx] => (item=CentOS-Debuginfo)
changed: [xxx.xxx.xxx.xxx] => (item=CentOS-Media)
changed: [xxx.xxx.xxx.xxx] => (item=CentOS-Vault)

TASK [dev-sec.os-hardening : get yum-repository-files] ***************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : activate gpg-check for config files] ****************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum.conf)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/dnf/dnf.conf)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum.repos.d/CentOS-Base.repo)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum.repos.d/CentOS-CR.repo)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum.repos.d/CentOS-Sources.repo)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum.repos.d/CentOS-fasttrack.repo)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum.repos.d/kubernetes.repo)
ok: [xxx.xxx.xxx.xxx] => (item=/etc/yum/pluginconf.d/rhnplugin.conf)

TASK [dev-sec.os-hardening : remove deprecated or insecure packages | package-01 - package-09] ***********************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [dev-sec.os-hardening : remove deprecated or insecure packages | package-01 - package-09] ***********************************************************************************************************************************************
skipping: [xxx.xxx.xxx.xxx]

PLAY [webservers] ****************************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [install python] ************************************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Update all packages] *******************************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Ensure a list of yum packages are installed] *******************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Add Docker repo] ***********************************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Install the latest version of docker-ce docker-ce-cli containerd.io] *******************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Install Docker SDK for Python] *********************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Start Docker service] ******************************************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

PLAY [webservers] ****************************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx]

TASK [Start nginx container with healthstatus] ***********************************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [Count all words of nginx container's default http page in alphabet order.] *************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [debug] *********************************************************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => {
    "msg": [
        "Words count: ['54']"
    ]
}

TASK [Sort all words of nginx container's default http page in alphabet order.] **************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

TASK [debug] *********************************************************************************************************************************************************************************************************************************
ok: [xxx.xxx.xxx.xxx] => {
    "msg": [
        "Sorted words: ['35em;', 'and', 'Arial,', 'at', 'auto;', 'available', 'body', 'Commercial', 'configuration', 'documentation', 'font-family:', 'for', 'For', 'Further', 'If', 'installed', 'is', 'margin:', 'nginx', 'nginx!', 'nginx.', 'nginx.com.', 'nginx.org.', 'online', 'page,', 'please', 'refer', 'required.', 'sans-serif;', 'see', 'server', 'successfully', 'support', 'Tahoma,', 'Thank', 'the', 'this', 'to', 'using', 'Verdana,', 'web', 'Welcome', 'width:', 'working.', 'you']"
    ]
}

TASK [Logs the container's resource usage every 10 seconds.] *********************************************************************************************************************************************************************************
changed: [xxx.xxx.xxx.xxx]

PLAY RECAP ***********************************************************************************************************************************************************************************************************************************
xxx.xxx.xxx.xxx             : ok=56   changed=29   unreachable=0    failed=0    skipped=26   rescued=0    ignored=0
localhost                  : ok=5    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```
