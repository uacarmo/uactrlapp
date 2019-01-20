package br.ufpe.gprt.uactrlapp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;

import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.Flood;
import org.opendaylight.controller.sal.action.SetDlDst;
import org.opendaylight.controller.sal.action.SetDlSrc;
import org.opendaylight.controller.sal.action.SetNwDst;
import org.opendaylight.controller.sal.action.SetNwSrc;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;

import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;

import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.packet.TCP;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
//import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import org.opendaylight.controller.sal.utils.EtherTypes;

public class PacketHandler implements IListenDataPacket {

    private static final Logger log = LoggerFactory.getLogger(PacketHandler.class);

    private IDataPacketService dataPacketService;
    private IFlowProgrammerService flowProgrammerService;
   // private ISwitchManager switchManager;

    static private InetAddress intToInetAddress(int i) {
        byte b[] = new byte[] { (byte) ((i>>24)&0xff), (byte) ((i>>16)&0xff), (byte) ((i>>8)&0xff), (byte) (i&0xff) };
        InetAddress addr;
        try {
            addr = InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            return null;
        }

        return addr;
    }

    /*
     * Sets a reference to the requested DataPacketService
     * See Activator.configureInstance(...):
     * c.add(createContainerServiceDependency(containerName).setService(
     * IDataPacketService.class).setCallbacks(
     * "setDataPacketService", "unsetDataPacketService")
     * .setRequired(true));
     */
    void setDataPacketService(IDataPacketService s) {
        log.trace("Set DataPacketService.");

        dataPacketService = s;
    }

    /*
     * Unsets DataPacketService
     * See Activator.configureInstance(...):
     * c.add(createContainerServiceDependency(containerName).setService(
     * IDataPacketService.class).setCallbacks(
     * "setDataPacketService", "unsetDataPacketService")
     * .setRequired(true));
     */
    void unsetDataPacketService(IDataPacketService s) {
        log.trace("Removed DataPacketService.");

        if (dataPacketService == s) {
            dataPacketService = null;
        }
    }


    /**
     * Sets a reference to the requested FlowProgrammerService
     */
    void setFlowProgrammerService(IFlowProgrammerService s) {
        log.trace("Set FlowProgrammerService.");
        flowProgrammerService = s;
    }

    /**
     * Unsets FlowProgrammerService
     */
    void unsetFlowProgrammerService(IFlowProgrammerService s) {
        log.trace("Removed FlowProgrammerService.");

        if (flowProgrammerService == s) {
            flowProgrammerService = null;
        }
    }

    /**
     * Sets a reference to the requested SwitchManagerService
     */
  /*  void setSwitchManagerService(ISwitchManager s) {
        log.trace("Set SwitchManagerService.");

        switchManager = s;
    }

    /**
     * Unsets SwitchManagerService

    void unsetSwitchManagerService(ISwitchManager s) {
        log.trace("Removed SwitchManagerService.");

        if (switchManager == s) {
            switchManager = null;
        }
    }
*/
    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        log.trace("Received data packet.");


        // The connector, the packet came from ("port")
        NodeConnector ingressConnector = inPkt.getIncomingNodeConnector();
        // The node that received the packet ("switch")
        Node node = ingressConnector.getNode();

        // Use DataPacketService to decode the packet.
        Packet pkt = dataPacketService.decodeDataPacket(inPkt);
        System.out.println("\nReceived packet ==> " + pkt);
        //System.out.println("Packet ==> " + pkt.getRawPayload());

        if (pkt instanceof Ethernet) {

            Ethernet  ethFrame = (Ethernet)  pkt;
            int etype = ethFrame.getEtherType() & 0xffff;

            // System.out.println("Ether Type ==> " + etype);

            if (etype == 2054) {
                System.out.println("Pacote " + ethFrame.getPayload());
            }

             if (etype == 34958) {
                  byte [] eappkt = (ethFrame.getRawPayload()) ;

                  short eapoltp = eappkt[1];
                  int eapolength = eappkt[2] * 256 + eappkt[3];
                  String eapolType = "";
                  int eapLength = 0;
                  String eapcode = "";
                  String eaptype ="";

            // add flow uac

                    Match match = new Match();
                    match.setField(MatchType.IN_PORT, ingressConnector);
                    match.setField(MatchType.DL_TYPE,  (short) 0x888e );
                    //match.setField(MatchType.NW_SRC, clientAddr);

                    List<Action> actions = new LinkedList<Action>();
                    actions.add(new Flood());

                    Flow flow = new Flow(match, actions);
                    Status status = flowProgrammerService.addFlow(node, flow);
                    if (!status.isSuccess()) {
                    log.error("Could not program flow: " + status.getDescription());
                    //return PacketResult.CONSUME;
                    }



                      if (eapoltp == 0){
                        short eapcd = eappkt[4];
                        short eapid = eappkt[5];
                        eapLength = eappkt[6] * 256 + eappkt[7];
                        eapolType = "EAP Packet (0)";
                            if  (eapcd == 1) {
                                    eapcode = "Request (1)";
                            }
                            else if (eapcd == 2){
                                    eapcode= "Response (2)";
                            }
                            else if (eapcd == 3){
                                    eapcode = "Sucess (3)";
                                }
                            else{
                                    eapcode = "Failure (4)";
                            }

                            if( eapolength  > 4){
                                  int  eaptp = eappkt[8];
                                  if (eaptp == 1){
                                         eaptype = "Identity (1)";
                                 }
                                else if (eaptp == 3){
                                         eaptype = "NAK (3)";
                                     }
                                else if (eaptp == 4){
                                         eaptype = "MD5-Challenger (4)";
                                     }
                                else if (eaptp == 13){
                                        eaptype = "TLS (13)";
                                    }
                                else if (eaptp == 25){
                                        eaptype = "EAP-PEAP (25)";
                                    }
                                else{
                                       eaptype = "NT";
                                   }

                            }

                      }
                      else if (eapoltp == 1){
                        eapolType = "EAPOL-Start (1)";
                      }
                      else if (eapoltp == 2){
                        eapolType = "EAPOL-Logoff (2)";
                       }
                       else if (eapoltp == 3){
                        eapolType = "EAPOL-Key (3)";
                        }
                        else{
                        eapolType = "EAPOL-Enc-Alert (4)";
                        }

                        if (eapoltp == 0 && eapolength > 4){
                         System.out.println("Pacote EAPOL ==> Version = " + eappkt[0] + " Type = " + eapolType + " Lenght = " + eapolength + " EAP Code= " + eapcode  + "EAP Type = " + eaptype + "EAP Length = " + eapLength );

                        }
                        else {
                         System.out.println("Pacote EAPOL ==> Version = " + eappkt[0] + " Type = " + eapolType + " Lenght = " + eapolength );
                        }

             }

            Object l3Pkt = ethFrame.getPayload();
            if (l3Pkt instanceof IPv4) {
                IPv4 ipv4Pkt = (IPv4) l3Pkt;
                int dstAddr = ipv4Pkt.getDestinationAddress();
                InetAddress addr = intToInetAddress(dstAddr);
                System.out.println("Pkt. to " + addr.toString() + " received by node " + node.getNodeIDString() + " on connector " + ingressConnector.getNodeConnectorIDString());
                return PacketResult.KEEP_PROCESSING;
            }
        }
        // We did not process the packet -> let someone else do the job.
        return PacketResult.IGNORED;
    }
}