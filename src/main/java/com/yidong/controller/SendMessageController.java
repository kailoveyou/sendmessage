package com.yidong.controller;

import com.yidong.utils.PropConf;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Administrator on 2019/2/12.
 */
@RequestMapping("sendMessage")
@RestController
public class SendMessageController {

    @PostConstruct
    public void sendMessage() throws InterruptedException, ParseException {
        // 获取 Spring Boot 上下文
        AnnotationConfigApplicationContext context =
                new AnnotationConfigApplicationContext(PropConf.class);

        //读取配置文件中的数据
        PropConf resourceService = context.getBean(PropConf.class);
        String port = resourceService.getPort();
        String address = resourceService.getAddress();

        DatagramSocket ds = null;
        try {
            ds = new DatagramSocket();
            // 创建一个数据报，每一个数据报不能大于64k，都记录着数据信息，发送端的IP、端口号，以及要发送到
            // 的接收端的IP、端口号。

            //用于测试单位的假数据
            String dataList1 = "<57>2018-12-25 15:15:17 172.16.101.12 %%--PROBE/DETECT/1/SIP-LIST:" +
                    " Anomaly ID:995; Creation Time:Tue Dec 25 15:13:09 2018;" +
                    " Update Time:Tue Dec 25 15:15:11 2018; DIP:183.213.92.228;" +
                    " Type:Traffic Anomaly; Sub-type:TCP SYN Flood; Direction:Incoming;" +
                    " Status:Ongoing;"+
                    " TOPIPData:" +
                    "{\"TOPIPData\":[{\"SIPOrDIP\":\"218.206.178.194\",\"bps\":\"1388k\",\"pps\":\"1k\"}," +
                    "{\"SIPOrDIP\":\"218.206.179.101\",\"bps\":\"42k\",\"pps\":\"150\"}]};" +
                    " SourcePortData:" +
                    "{\"sourcePortData\":[{\"bps\":\"9k\",\"port\":\"39718\",\"pps\":\"33\",\"protocol\":\"UDP\"}," +
                    "{\"bps\":\"9k\",\"port\":\"30502\",\"pps\":\"33\",\"protocol\":\"UDP\"}," +
                    "{\"bps\":\"9k\",\"port\":\"12070\",\"pps\":\"33\",\"protocol\":\"UDP\"}," +
                    "{\"bps\":\"9k\",\"port\":\"60710\",\"pps\":\"33\",\"protocol\":\"UDP\"}," +
                    "{\"bps\":\"8k\",\"port\":\"34444\",\"pps\":\"33\",\"protocol\":\"UDP\"}]};" +
                    " DestinationPortData:" +
                    "{\"destinationPortData\":[{\"bps\":\"3099k\",\"port\":\"10053\",\"pps\":\"12250\",\"protocol\":\"UDP\"}," +
                    "{\"bps\":\"2674k\",\"port\":\"11022\",\"pps\":\"3k\",\"protocol\":\"TCP\"}]};";

            String realTImeAlarm1 = getAlarmRealTimeMessage("6","Mon Apr 1 12:31:50 2019", "Mon Apr 1 12:31:50 2019", "ICMP Flood",
                    "0", "0", "183.213.92.228", "", "", "");
            String realTImeAlarm2 = getAlarmRealTimeMessage("6","Mon Apr 1 12:31:50 2019", "Mon Apr 1 12:32:51 2019", "ICMP Flood",
                    "0", "0", "183.213.92.228", "194.210.59.185", "194.210.1.33", "194.209.182.233");
            String realTImeAlarm3 = getAlarmRealTimeMessage("6","Mon Apr 1 12:31:50 2019", "Mon Apr 1 12:33:51 2019", "ICMP Flood",
                    "0", "0", "183.213.92.228", "195.103.29.1", "195.102.222.129", "195.102.167.209");
            String realTImeAlarm4 = getAlarmRealTimeMessage("6","Mon Apr 1 12:31:50 2019", "Mon Apr 1 12:40:51 2019", "ICMP Flood",
                    "0", "1", "183.213.92.228", "217.44.51.241", "217.44.36.81", "217.44.8.249");
            String realTImeAlarm5 = getAlarmRealTimeMessage("7","Mon Apr 1 12:31:50 2019", "Mon Apr 1 12:41:51 2019", "Host Total Traffic",
                    "0", "0", "183.213.92.228", "217.44.51.241", "217.44.36.81", "217.44.8.249");

            String ipTraffic1 = getTrafficMessage("183.213.92.228", "Mon Apr 1 12:32:05 2019", "ICMP Flood",
                    "0", "880000", "2223584000");
            String ipTraffic2 = getTrafficMessage("183.213.92.228", "Mon Apr 1 12:32:35 2019", "ICMP Flood",
                    "0", "3533000", "4005360000");
            String ipTraffic3 = getTrafficMessage("183.213.92.228", "Mon Apr 1 12:33:05 2019", "ICMP Flood",
                    "0", "861000", "2176512000");
            String ipTraffic4 = getTrafficMessage("183.213.92.228", "Mon Apr 1 12:33:35 2019", "ICMP Flood",
                    "0", "2571000", "1726944000");
            String ipTraffic5 = getTrafficMessage("183.213.92.228", "Mon Apr 1 12:34:05 2019", "ICMP Flood",
                    "0", "2597000", "1744976000");

            String cleanIpTraffic1 = getCleanTrafficMessage("183.213.92.228", "Mon Apr 1 12:35:05 2019", "ICMP Flood",
                    "1040843040", "1318784", "425330", "502");
            String cleanIpTraffic2 = getCleanTrafficMessage("183.213.92.228", "Mon Apr 1 12:35:35 2019", "ICMP Flood",
                    "788334640", "110208", "1331787", "201");

            String hw1 = "<189>2019-03-22 11:44:48 192.168.110.1 %%01SEC/5/ATCKDF(l):log_type=ip_attack_sum device_ip=192.168.110.1 device_type=CLEAN zone_id=12 zone_name=w100 zone_ip=192.168.111.110 start_time=\"2019-03-22 11:44:47\" end_time=\"\" severity=3 max_severity=3 in_pps=5938 in_kbps=68008 drop_pps=0 drop_kbps=0 max_in_pps=8320 max_in_kbps=95290 curr_conn=0 new_conn=0 attack_type=\"10\" ";
            String hw2 = "<189>2019-03-22 11:45:37 192.168.110.1 %%01SEC/5/ATCKDF(l):log_type=ip_flow time=\"2019-03-22 11:45:37\" device_ip=192.168.110.1 device_type=CLEAN zone_id=12 zone_name=w100 zone_ip= biz_id=0 is_deszone=true is_ipLocation=false ipLocation_id=0 total_pps=9856 total_kbps=112882 tcp_pps=2176 tcp_kbps=1326 tcpfrag_pps=2176 tcpfrag_kbps=1326 udp_pps=9856 udp_kbps=112882 udpfrag_pps=0 udpfrag_kbps=0 icmp_pps=0 icmp_kbps=0 other_pps=0 other_kbps=0 syn_pps=2176 synack_pps=0 ack_pps=0 finrst_pps=0 http_pps=0 http_kbps=0 http_get_pps=0 https_pps=0 https_kbps=0 dns_request_pps=0 dns_request_kbps=0 dns_reply_pps=0 dns_reply_kbps=0 sip_invite_pps=0 sip_invite_kbps=0 tcp_increase_con=0 udp_increase_con=0 icmp_increase_con=0 other_increase_con=0 tcp_concur_con=0 udp_concur_con=0 icmp_concur_con=0 other_concur_con=0 ";
            String hw3 = "<189>2019-03-22 11:45:37 192.168.110.1 %%01SEC/5/ATCKDF(l):log_type=ip_drop time=\"2019-03-22 11:45:37\" device_ip=192.168.110.1 device_type=CLEAN zone_id=12 zone_name=w100 zone_ip=192.168.111.110 biz_id=2 is_deszone=false is_ipLocation=false ipLocation_id=0 total_pps=19456 total_kbps=11856 tcp_pps=19456 tcp_kbps=11856 tcpfrag_pps=19456 tcpfrag_kbps=11856 udp_pps=0 udp_kbps=0 udpfrag_pps=0 udpfrag_kbps=0 icmp_pps=0 icmp_kbps=0 other_pps=0 other_kbps=0 syn_pps=19456 synack_pps=0 ack_pps=0 finrst_pps=0 http_pps=0 http_kbps=0 http_get_pps=10 https_pps=0 https_kbps=0 dns_request_pps=0 dns_request_kbps=0 dns_reply_pps=0 dns_reply_kbps=0 sip_invite_pps=0 sip_invite_kbps=0 ";
            String hw4 = "<189>2019-03-22 11:45:37 192.168.110.1 %%01SEC/5/ATCKDF(l):log_type=ip_attack device_ip=192.168.110.1 device_type=DETECT zone_id=12 zone_name=w100 zone_ip=192.168.111.110 start_time_alert=\"2019-03-22 11:44:47\" start_time_attack=\"2019-03-22 11:44:47\" end_time=\"\" duration=37 attack_type=10 protocol=0 port=0 attack_status=ATTACK drop_packets=329216 drop_kbits=200616 attacker=192.172.82.97,192.172.78.121,192.172.74.145,192.172.58.241,192.172.86.73,192.172.66.193,192.172.94.25,192.172.62.217,192.172.70.169,192.172.90.49 ";

            byte[] b = null;
//            b = hw2.getBytes();
//            sendMessage(port, address, ds, b);
//            System.out.println("消息上报成功!");
//            b = hw3.getBytes();
//            sendMessage(port, address, ds, b);
//            System.out.println("消息上报成功!");
//            Thread.sleep(20000);
            b = hw4.getBytes();
            sendMessage(port, address, ds, b);
            System.out.println("消息上报成功!");

//            b = ipTraffic1.getBytes();
//            sendMessage(port, address, ds, b);
//            System.out.println("消息上报成功!");
//            b = ipTraffic2.getBytes();
//            sendMessage(port, address, ds, b);
//            System.out.println("消息上报成功!");

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("消息上报失败!");
        } finally {
            if (ds != null) {
                ds.close();
            }
        }
    }

    private void sendMessage(String port, String address, DatagramSocket ds, byte[] b) throws IOException {
        DatagramPacket pack = new DatagramPacket(b, 0, b.length,
                InetAddress.getByName(address), Integer.parseInt(port));
        ds.send(pack);
    }

    /**
     * 获取CleanTraffic数据
     * @param ip
     * @param createTime
     * @param attackType
     * @param beforebits
     * @param afterbits
     * @param beforePackets
     * @param afterPackets
     * @return
     * @throws ParseException
     */
    public String getCleanTrafficMessage(String ip,String createTime,String attackType,String beforebits,String afterbits,
                                         String beforePackets,String afterPackets) throws ParseException {
        //拼接字符串
        String data = "<57>2018-12-25 15:16:58 221.178.162.2 %%--GUARD/DETECT/1/TRAFFIC:IP" +
                " address:"+ ip +";Creation Time:"+ createTime +";" +
                "Traffic Type:"+ attackType +";Packets before cleaning:"+beforePackets+";" +
                "bits before cleaning:"+beforebits+";Packets after cleaning:"+afterPackets+";" +
                "bits after cleaning:"+afterbits+"";
        return data;
    }


    /**
     * 获取traffic数据
     * @param ip
     * @param createTime
     * @param attackType
     * @param direction
     * @param Packets
     * @param bits
     * @return
     * @throws ParseException
     */
    public String getTrafficMessage(String ip,String createTime,String attackType,String direction,String Packets,String bits) throws ParseException {
        //流向
        if(direction.trim().equals("0")){
            direction = "Incoming";
        }else{
            direction = "Outgoing";
        }
        //拼接字符串
        String data = "<57>2018-12-25 15:17:05 221.181.218.86 %%--PROBE/DETECT/1/TRAFFIC:IP"+
                " address:"+ ip +";Creation Time:"+ createTime +";" +
                "Traffic Type:"+ attackType +";Direction:"+ direction +";" +
                "Packets:"+ Packets +";bits:"+ bits +"";
        return data;
    }

    /**
     * 获取实时告警数据
     * @param createTime
     * @param updateTime
     * @param subType
     * @param direction
     * @param status
     * @param dip
     * @param sip1
     * @param sip2
     * @param sip3
     * @return
     * @throws ParseException
     */
    public String getAlarmRealTimeMessage(String id,String createTime,String updateTime,String subType,String direction,String status,
                                  String dip,String sip1,String sip2,String sip3) throws ParseException {
        //流向
        if(direction.trim().equals("0")){
            direction = "Incoming";
        }else{
            direction = "Outgoing";
        }
        //状态
        if(status.trim().equals("0")){
            status = "Ongoing";
        }else{
            status = "Obsolete";
        }
        String data = "<57>2019-04-01 12:41:51 192.168.108.163 %%--PROBE/DETECT/1/ALARM: Anomaly ID:"+id+";" +
                " Creation Time:"+ createTime +"; Update Time:"+ updateTime +"; Type:Traffic Anomaly; " +
                "Sub-type:"+ subType +"; Severity:normal; Status:"+ status +"; Direction:"+ direction +"; Resource:; Resource ID:; " +
                "Importance:High; Current:; Threshold:567; Unit:pps; DIP1:"+ dip +"; DIP2:; DIP3:; DPort1:; DPort2:; " +
                "SIP1:"+sip1+"; SIP2:"+sip2+"; SIP3:"+sip3+"; SPort1:; SPort2:; Protocol:; URL to Link the Report:www.dptech.com";
        return data;
    }


    public static void main(String[] args) {
        Date date = new Date();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String format = simpleDateFormat.format(date);
        System.out.println(format);

    }

}
