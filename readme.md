# Obligatory legal text
The device mentioned in this page, Tilgin HG2331, has an EULA stating that reverse engineering is strictly prohibited. I have complied with the EULA and never touched the software that is bundled with the device.

# Home Gateway Security, Türk Telekom Style

Türk Telekom _(a major ISP in Turkey, also known with the name TTNET)_ gives its FTTB/FTTH customers one of three Home Gateways (HGWs). One is from TP-Link, the other is from Zyxel and the last one is from Tilgin. I'll be focusing on the Tilgin one, the HG2331.

_**Abstract (or tl;dr):**_ Türk Telekom uses TR069 **without SSL** to provision its Tilgin HGWs. The provisioning data contains the password for the `root` account and more.


## How It All Started

I bought a Mikrotik RouterBoard some time ago, I had it as my main Fiber Router since then. But I was using the ISP issued Tilgin HG2331 as a bridge (the fourth port on the HGW is used for that). I got annoyed so I challenged myself to remove this slow middleman.

### Challenge #1: How am I supposed to bridge a port to WAN on RouterOS?

Well, It was simple after messing with it for couple of days.

```routeros
/interface bridge add name=bridgeForGoodStuff protocol-mode=none
/interface bridge port add bridge=bridgeForGoodStuff interface=ether1
/interface bridge port add bridge=bridgeForGoodStuff interface=ether5
```

`ether1` is the WAN of the RouterBoard. Connect the HGW's WAN to `ether5`.

### Challenge #2: How am I gonna sniff the traffic of this bridge?

Well, you need to have a MicroSD card for this if you have a low capacity model RouterBoard.

```routeros
/tool sniffer set file-limit=1000000000KiB file-name=disk1/pdump.pcapng filter-interface=ether5 streaming-enabled=yes streaming-server=192.168.88.15
```

Change `192.168.88.15` to your Wireshark host's IP. Disable the WCCP protocol on Wireshark _(Analyze/Enabled Protocols)_ and use `udp port 37008` filter on your interface. Then you just do:

```routeros
/tool sniffer start
```

### Mistake: Bridge collision on `ether5` 

This caused the HGW to get an IP address from my internal network and think that my RouterBoard is a TR069 server. Luckily RouterOS responded with `Not Implemented`.

This mistake also led the HGW to re-provision itself. More on that later.

### Epic Win Caused by that Mistake

After I fixed my bridge I saw an unusual exchange, an unencrypted HTTP/XML data between the TR069 server and the HGW. After many reboots on the HGW, I couldn't get the same exchange. Probably the HGW asks the TR069 server if the configuration has changed. But hey, I got more data than I normally would get. Let's dig deeper.

## Would you look at that: The Provisioning Configuration

63 XML packets went through and this is most interesting one.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <SOAP-ENV:Header>
        <cwmp:HoldRequests SOAP-ENV:mustUnderstand="1">0</cwmp:HoldRequests>
        <cwmp:ID SOAP-ENV:mustUnderstand="1">5</cwmp:ID>
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
        <cwmp:SetParameterValues>
            <ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[12]">
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.1.Enable</Name>
                    <Value xsi:type="xsd:boolean">1</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.1.Username</Name>
                    <Value xsi:type="xsd:string">Tekniker</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.1.Password</Name>
                    <Value xsi:type="xsd:string">Teknik_br04</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.1.X_000261_AccessLevel</Name>
                    <Value xsi:type="xsd:string">Administrator</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.2.Enable</Name>
                    <Value xsi:type="xsd:boolean">1</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.2.Username</Name>
                    <Value xsi:type="xsd:string">admin</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.2.Password</Name>
                    <Value xsi:type="xsd:string">admin</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.2.X_000261_AccessLevel</Name>
                    <Value xsi:type="xsd:string">User</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.3.Enable</Name>
                    <Value xsi:type="xsd:boolean">1</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.3.Username</Name>
                    <Value xsi:type="xsd:string">root</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.3.Password</Name>
                    <Value xsi:type="xsd:string">fTTh_b2013</Value>
                </ParameterValueStruct>
                <ParameterValueStruct>
                    <Name>InternetGatewayDevice.User.3.X_000261_AccessLevel</Name>
                    <Value xsi:type="xsd:string">Maintainer</Value>
                </ParameterValueStruct>
            </ParameterList>
            <ParameterKey />
        </cwmp:SetParameterValues>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

To put simply,
```
# This account can access all the hardware on the HGW.
root : fTTh_b2013

# This account can only access normal admin stuff.
Tekniker : Teknik_br04

# Admin but not so admin.
admin : admin
```

## Concluding My Challenge

While I was packet sniffing with a rather janky setup to temporarily get to the Internet (RouterBoard WAN to ether5 bridge, then HGW port4 to RouterBoard ether2), I saw a PPPoE discorvery packet on a VLAN. I disconnected the HGW, set up the VLAN and the PPPoE client and it worked. No more middlemans.

### So I got the config and didn't use it, right? Wrong.

The configuration also had the **full VoIP config**. [Zyxel Turkey has a video](https://www.youtube.com/watch?v=VnaQ6u_pUzM) on how to set the VoIP up but it doesn't show almost anything in the config I got. With some trial and error, I managed to get VoIP working on my computer.

Not gonna explain the how-to on RouterOS but I will give the necessary things to know.

* VoIP is a private network under the VLAN ID 46. It has DHCP but you might want to spoof (or rather clone) the DHCP Request List and the Client ID.
* You have to sacrifice the entire `10.0.0.0/8` range as the VoIP network uses SRV records (on domain `ttimscore.com.tr`).
* Use a Layer7 (or mangle) rule(s) to determine the requests to `ttimscore.com.tr` and `10.in-addr.arpa`.
* If the L7 rule(s) gets requests that are DNS requests, redirect those to the DNS of the VoIP network using `dst-nat`. The DNS address may change in different regions of the country.
* Masquerade the 10.0.0.0/8 block using the VLAN as the output interface (on NAT).

Then, use an app like [X-Lite](https://www.counterpath.com/x-lite/) from CounterPath to connect to the VoIP network.

Here are the settings for X-Lite:

```
User ID: <Phone number, starting with +90>
Domain: ttimscore.com.tr
Password: <Last 4 digits of the phone number>
Display name: <Phone number, starting with +90>@ttimscore.com.tr
Authorization name: <Phone number, starting with +90>@ttimscore.com.tr

Enable domain proxy and use the proxy address on the HGW.
The format for it is: <region>.<province>.ttimscore.com.tr

Transport/Transport: UDP
Topology/Firewall Traversal: None
Advanced/Connection Management:
  * Send SIP keep-alives
  * Use rport
```

## What can happen with this info?

Many things. Someone with malicious intents can wreck everything up.

## Solution

Basically, use SSL and don't store any private keys (in plaintext) on the HGW.

## It looks like Türk Telekom didn't care any of this.

**UPDATE**: Appearently the VLAN used for Internet connection is visible to the user on the TP-Link HGW, how neat. This confirmed the topic I wanted to talk about, again.

All the things you see here were reported to Türk Telekom. However I got no updates from them.

This was my very first "disclosure" so I am a total noob at this.

I reported my original issue on 22nd of April, 2018 at 22:36 (All times are GMT+3) using the web form [here](https://www.turktelekom.com.tr/destek/sayfalar/kurum-disi-olay-bildirim-formu.aspx). I gave the company 90 days to fix and inform me. At the time I reported it, the web form had a broken time input, so I had to modify it using JavaScript:

```js
WebForm_GetElementById("ctl00_ctl23_g_ccc4e5b6_aefb_44da_a469_038958ede66c_ctl00_txtEventDateTime").value = "21:00"
```

[I also used Twitter. (ps: Translation of the tweet is not bad)](https://twitter.com/linuxgemini/status/988120995990040576) A support rep called me on 23rd of April, 2018 at 14:04. I talked through the issue but I believe that I couldn't report the issue correctly. Then, radio silence.

On 26th of May 2018 at 17:07, I sent the same report using the same web form. But this time, the broken time input is fixed somehow. [I also sent a tweet to the CEO of Türk Telekom, Paul Doany, thinking that this may speed things up.](https://twitter.com/linuxgemini/status/1000390236130762752)

It did, he responded to me immediately over PM asking my phone number. I gave the number and also an overview of the issue by stripping away the sensitive data and giving some analytics (using Shodan). Got a call from a rep on the same day, at 18:15. I said what I said on April. This time I kindly asked the rep to give me updates, at least on SMS. The rep agreed but again, radio silence happened.


~~For a number of reasons, I didn't try to plug in the HGW again.~~

I did turn the HGW on, nothing had changed.

If a company pushing future technologies like 5G and IPv6 for **businesses only**, there is literally reason for us individual customers to use the company's services.

For example the RFC3068 6to4 relay address 192.88.99.1 (deprecated with RFC7526, but no enforced shutdown) is broken, only in connections with Türk Telekom. This may be caused by Hurricane Electric but I am not so sure.

But because Türk Telekom is the only choice for most people in big regions, people are forced to use Türk Telekom (this has changed a little after an agreement for connection sharing between ISPs is signed).


## The guilt in me

I didn't want to release this. However, the more people having all kinds of issues with their HGW, I **needed** to release this. I am a student, I must be studying. But the guilt in me always pushes me to help everyone in any field that I have some experience of.

For example, somehow someone got root access on the HGW and asked for a help: https://forum.donanimhaber.com/ttnet-tilgin-modem-den-kurtulmak-icin-mac-kloning-yardim--133039920

I helped that someone. They are happy, I am happy.
