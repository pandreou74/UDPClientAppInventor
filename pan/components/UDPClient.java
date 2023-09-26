    //      ---------------------------------------------------
    //            UDP Client Component for App Inventor
    //      ---------------------------------------------------
    //          Copyright (C) <2017-2023>
    //          Author : Andreou Pantelis
    
    //  This program is free software: you can redistribute it and/or modify
    //  it under the terms of the GNU General Public License as published by
    //  the Free Software Foundation, either version 3 of the License, or
    //  any later version.
    
    //  This program is distributed in the hope that it will be useful,
    //  but WITHOUT ANY WARRANTY.
    
    //  You should have received a copy of the GNU General Public License
    //  along with this program.  If not, see <http://www.gnu.org/licenses/>.
      
      
package pan.components.UDPClient;
        
import static android.Manifest.permission.ACCESS_NETWORK_STATE;
import static android.Manifest.permission.ACCESS_WIFI_STATE;
import static android.Manifest.permission.INTERNET;


import com.google.appinventor.components.runtime.*;
import com.google.appinventor.components.runtime.errors.YailRuntimeError;
import com.google.appinventor.components.annotations.DesignerProperty;

import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesPermissions;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.common.YaVersion;
import com.google.appinventor.components.runtime.util.AsynchUtil;
import com.google.appinventor.components.runtime.util.ErrorMessages;
import com.google.appinventor.components.runtime.util.SdkLevel;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;
import com.google.appinventor.components.runtime.util.ElementsUtil;
import com.google.appinventor.components.runtime.util.YailList;

import java.io.IOException;
import java.util.Enumeration;

import java.io.*;
import java.net.*;
import java.util.logging.Level;
import java.util.logging.Logger;

@DesignerComponent(version = 1, 
                   description = "A component to send UDP Datagrams Unicast Or Broadcast. " + 
                              "After send if property WantResponce is true you can receive the responce from remote server .", 
                   category = ComponentCategory.EXTENSION, 
                   nonVisible = true, 
                   iconName = "pic_icons/UDPClient.png")

@SimpleObject(external = true)
@UsesPermissions(permissionNames = "android.permission.INTERNET, android.permission.ACCESS_NETWORK_STATE ,android.permission.WRITE_EXTERNAL_STORAGE, android.permission.READ_EXTERNAL_STORAGE")

public class UDPClient extends AndroidNonvisibleComponent implements ActivityResultListener, Component {

    private final ComponentContainer container;
    private final Activity activity;

    private String HostNameOrIP;
    private int HostPort;
    private String broadcastIP;
    private DatagramSocket udpSockSession;
    private InetAddress SessionHostAddress;
    private int SessionHostPort;
    // private DatagramPacket packet;

    private boolean want_Responce;
    private boolean want_BroadcastResponce;
    private int timeOutForResponce_Msec;
    private boolean showErrorsInForm ;
    
    private ByteArrayOutputStream baout;
    private DataOutputStream dataBuf;
    // private ByteBuffer dataBuf; //=new 4464-20 //TokenRing MTU

    private Thread sessionThread;
    private static final int NO_SESION = 0;
    private static final int SESION_OPENED = 1;
    private static final int SESION_ERROR = 2;
    private static final int SESION_TO_CLOSE = 3;
    private static final int SESION_CLOSED = 4;

    private int sesionStatus = NO_SESION;
    private static final int SESION_WANT_SEND = 1;
    private static final int SESION_ACCEPT_SEND = 2;
    private static final int SESION_WAIT_RECEIVE = 3;
    private int session_action = 0;

    private static final String LOG_TAG = "UDPClientt";

    final static char[] Hex_Digits = "0123456789ABCDEF".toCharArray();

    private static final String MyEmail = "pan.appinventor@gmail.com";
    private static final String MyName = "Andreou Pantelis";
    private static final String ExtensionName = "UDP Client";
    private static final String aboutExt = ExtensionName + " by " + MyName + ". Email:" + MyEmail;

    public UDPClient(ComponentContainer container) {
        super(container.$form());
        this.container = container;

        this.HostNameOrIP = "192.168.2.100";
        this.HostPort = 1024;
        this.broadcastIP = "255.255.255.255";
        this.want_Responce = true;
        this.want_BroadcastResponce = true;
        this.timeOutForResponce_Msec = 2000;
        this.udpSockSession = null;
        this.showErrorsInForm = false;
        

        this.baout = null;
        this.dataBuf = null;

        activity = (Activity) this.container.$context();

    }

    @Override
    public void resultReturned(int requestCode, int resultCode, Intent data) {
        // TODO Auto-generated method stub
    }

    /**
     * Returns info About this Extension.
     */
    @SimpleProperty(category = PropertyCategory.UNSET, description = "About this Extension")
    public String AboutExtension() {
        return aboutExt;
    }

    /**
     * info About this Extension.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING, defaultValue = aboutExt)
    @SimpleProperty
    public void AboutExtension(String ab) {
        // do nothing
    }

    /**
     * Returns the HostAddress.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "The destination Host Address as  Name Or IP.")
    public String HostAddress() {
        return this.HostNameOrIP;
    }

    /**
     * Specifies the HostAddress as Name Or IP.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING, defaultValue = "192.168.2.100")
    @SimpleProperty
    public void HostAddress(String hostip) {
        this.HostNameOrIP = hostip;
    }

    /**
     * Returns the Remote Port of destination.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "The Remote Port of the destination.")
    public int RemotePort() {
        return this.HostPort;
    }

    /**
     * Specifies the Remote Port of destination..
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_NON_NEGATIVE_INTEGER, defaultValue = "1024")
    @SimpleProperty
    public void RemotePort(int port) {
        this.HostPort = port;
    }

    /**
     * Returns the BroadCastIP.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "The BroadCast IP for broadcast datagram packet.")
    public String BroadCastIP() {
        return this.broadcastIP;
    }

    /**
     * Specifies the URL.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_STRING, defaultValue = "255.255.255.255")
    @SimpleProperty
    public void BroadCastIP(String hostip) {
        this.broadcastIP = (hostip == null) ? "255.255.255.255" : hostip;
        // if(isIP(hostip)==true)
        // this.broadcastIP = hostip;
    }

    /**
     * Specifies the port.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_NON_NEGATIVE_INTEGER, defaultValue = "2000")
    @SimpleProperty
    public void WaitTimeForResponceMsec(int ms) {
        this.timeOutForResponce_Msec = ms;
    }

    /**
     * Returns the WaitTimeForResponceMsec.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "The Time(in milliSeconds) to receive Responce (if WantResponce=true).")
    public int WaitTimeForResponceMsec() {
        return this.timeOutForResponce_Msec;
    }

    /**
     * Specifies the if want to wait for receive responce.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_BOOLEAN, defaultValue = "True")
    @SimpleProperty
    public void WantResponce(boolean wait) {
        this.want_Responce = wait;
    }

    /**
     * Returns the WantResponce.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "Specifies if want to receive respond or close the socket after send data.")
    public boolean WantBroadcastResponce() {
        return this.want_BroadcastResponce;
    }

    /**
     * Specifies the if want to wait for receive responce.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_BOOLEAN, defaultValue = "True")
    @SimpleProperty
    public void WantBroadcastResponce(boolean wait) {
        this.want_BroadcastResponce = wait;
    }

    /**
     * Returns the WantResponce.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "Specifies if want to receive respond or close the socket after send data.")
    public boolean WantResponce() {
        return this.want_Responce;
    }
    
    /**
     * Returns the ShowErrorOnScreen.
     */
    @SimpleProperty(category = PropertyCategory.BEHAVIOR, description = "Specifies if we want to to show errors in form.")
    public boolean ShowErrorsInForm() {
        return this.showErrorsInForm;
    }

    /**
     * Specifies if we want to to show errors in form.
     */
    @DesignerProperty(editorType = PropertyTypeConstants.PROPERTY_TYPE_BOOLEAN, defaultValue = "False")
    @SimpleProperty
    public void ShowErrorsInForm(boolean show) {
        this.showErrorsInForm = show;
    }


    public static boolean isNumeric(String string) {
        for (char c : string.toCharArray()) {
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /**
     * Specifies if a string isIP
     */
    private boolean isIP(String anIp) {
        if (anIp == null) {
            Log.e(LOG_TAG, "Null IP");
            if(this.showErrorsInForm)
                form.dispatchErrorOccurredEvent(UDPClient.this, "isIP", ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, "Null IP");

            return false;
        }

        String hostAdr = anIp.trim();
        if ((hostAdr.length() < 7) || (hostAdr.length() > 15)) {
            return false;
        }

        String[] split = hostAdr.split("\\.");
        if (split.length != 4) {
            return false;
        }

        for (int i = 0; i < 4; i++) {
            if (isNumeric(split[i]) == false) {
                return false;
            }
            try {
                int IpByte = Integer.parseInt(split[i]);
                if (IpByte < 0 || IpByte > 255) {
                    return false;
                }
            } catch (NumberFormatException nfe) {
                return false;
            }
        }

        return true;
    }

    /**
     * Initialize output streams
     */
    protected void InitOutBuf() {
        if (this.baout == null) {
            this.baout = new ByteArrayOutputStream();
        }
        if (this.dataBuf == null) {
            this.dataBuf = new DataOutputStream(this.baout);
        }

    }

    /**
     * bytes[] To Hex String
     */
    public static String bytesToHexString(byte[] bytes) {
        char[] hexChars = new char[(bytes.length * 2)];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;

            hexChars[2 * j] = Hex_Digits[v >> 4];
            hexChars[2 * j + 1] = Hex_Digits[v & 0x0F];

        }

        return new String(hexChars);
    }

    /**
     * GetBytesOutBufer
     */
    @SimpleFunction(description = "Get Bytes from Send bufer as String or as Hexadecimal String Bytew")
    public String GetBytesOutBufer(boolean asHex) {
        if (this.dataBuf != null) {
            if (asHex) {
                return bytesToHexString(this.baout.toByteArray());
            }
            return this.baout.toByteArray().toString();
        }

        return "";

    }

    @SimpleFunction(description = "Get preferred outbound IP")
    public String GetMyPreferredOutIP() {
        try {
            final DatagramSocket socket = new DatagramSocket();

            socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
            String ip = socket.getLocalAddress().getHostAddress();
            return ip;
        } catch (Exception e) {

        }
        return "";
    }

    @SimpleFunction(description = "Get All Network  IP")
    public YailList GetMyAllNetIPAddress() {

        String strIPs = "";
        Enumeration<NetworkInterface> e = null;
        try {
            e = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException socketException) {
            return YailList.makeEmptyList();
        }
        while (e.hasMoreElements()) {
            NetworkInterface n = (NetworkInterface) e.nextElement();
            //n.getInterfaceAddresses().
            Enumeration<InetAddress> ee = n.getInetAddresses();
            while (ee.hasMoreElements()) {
                InetAddress i = (InetAddress) ee.nextElement();
                
                if (strIPs.equals("") == true) {
                    strIPs = i.getHostAddress();
                } else {
                    strIPs = strIPs + "," + i.getHostAddress();
                }

                //System.out.println(i.getHostAddress());
            }
        }

        YailList IPitems = ElementsUtil.elementsFromString(strIPs);
        return IPitems;
    }

    /**
     * GetBytesOutBufer
     */
    @SimpleFunction(description = "Get Bytes Number (size-length) of the bufer")
    public int GetOutBuferSize() {
        if (this.dataBuf != null) {
            try {
                this.dataBuf.flush();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            // this.baout.toString().length();
            return this.baout.size();

        }

        return 0;

    }

    /**
     * ClearResetOutBufer
     */
    @SimpleFunction(description = "Clear and reset the output bufer used to send data")
    public void ClearResetOutBufer() {
        if (this.dataBuf != null) {
            try {
                this.dataBuf.close();
                this.baout.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        }
        this.dataBuf = null;
        this.baout = null;

    }

    @SimpleFunction(description = "Append UTF String to send Bufer.")
    public void AppendUTFString(String str) {
        InitOutBuf();
        try {
            dataBuf.writeUTF(str);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append String to send Bufer.")
    public void AppendString(String str) {
        InitOutBuf();
        try {
            dataBuf.writeBytes(str);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append Char to send Bufer.")
    public void AppendChar(int val) {
        InitOutBuf();
        try {
            dataBuf.writeChar(val);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append Chars to send Bufer.")
    public void AppendChars(String val) {
        InitOutBuf();
        try {
            dataBuf.writeChars(val);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append A Byte as Hexadecimal String Data to send Bufer.")
    public void AppendHexByte(String hexByte) {
        InitOutBuf();
        try {
            dataBuf.writeByte(Integer.parseInt(hexByte, 16));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append A Byte Data to send Bufer.")
    public void AppendByte(int aByte) {
        InitOutBuf();
        try {
            dataBuf.writeByte(aByte);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    // @SimpleFunction(description = "Send A String Data with UDP Datagram to
    // Destination.")
    // public void AppendList(YailList datList) {
    // datList.makeList(vals)
    // }
    @SimpleFunction(description = "Append An int Data to send Buffer.")
    public void AppendInt(int val) {
        InitOutBuf();
        try {
            dataBuf.writeInt(val);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append A float val Data to send Buffer.")
    public void AppendFloat(float val) {
        InitOutBuf();
        try {
            dataBuf.writeFloat(val);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append A Boolean value Data to send Bufer.")
    public void AppendBoolean(boolean data) {
        InitOutBuf();
        try {
            dataBuf.writeBoolean(data);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SimpleFunction(description = "Append Bytes(Byte sequence) as Hexadecimal String Data to send Bufer.")
    public void AppendHexBytes(String HexBytes) {
        InitOutBuf();
        String hexDigits = "0123456789ABCDEF";
        HexBytes = HexBytes.toUpperCase();
        int len = HexBytes.length();
        boolean validHex = true;
        for (int i = 0; i < len; i++) {
            int c = HexBytes.charAt(i);
            if (hexDigits.indexOf(c) == -1) {
                validHex = false;
                break;
            }
        }

        if (!validHex) {
            Log.e(LOG_TAG, "Not Valid Hex");
            if(this.showErrorsInForm)
                form.dispatchErrorOccurredEvent(UDPClient.this, "AppendBytes", ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED,
                    "Not Valid Hex");
            return;
        }

        if (len % 2 == 1) {
            HexBytes = "0" + HexBytes;
            len++;
        }

        for (int i = 0; i < len; i = i + 2) {
            String hexByte = HexBytes.substring(i, i + 2);
            try {
                dataBuf.writeByte(Integer.parseInt(hexByte, 16));
            } catch (NumberFormatException e) {
                Log.e(LOG_TAG, "Not Valid Hex", e);
                if(this.showErrorsInForm)
                    form.dispatchErrorOccurredEvent(UDPClient.this, "AppendBytes",
                        ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e.getMessage());
            } catch (IOException e) {
                Log.e(LOG_TAG, "Not Valid Hex", e);
                if(this.showErrorsInForm)
                    form.dispatchErrorOccurredEvent(UDPClient.this, "AppendBytes",
                        ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e.getMessage());
            }

        }
    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating that we have responce from a remote server after send a message.")
    public void GotResponce(String Responce) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "GotResponce", Responce);
    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating that we have responce after broadcasting .")
    public void GotBroadcasterResponce(String ResponderHost, int ResponderPort, String Responce) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "GotBroadcasterResponce", ResponderHost, ResponderPort, Responce);
    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating that the contents from the file have been read.")
    public void ResponcetError(String ErrMsg) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "ResponcetError", ErrMsg);
    }
  /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating that the contents from the file have been read.")
    public void BroadcastResponceError(String ErrMsg) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "BroadcastResponceError", ErrMsg);
    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating an error occur when trying to send data.")
    public void SendDataError(String ErrMsg) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "SendDataError", ErrMsg);
    }

    /**
     * AsyncReceiveRespond from remote udp server.
     *
     * @param sock the DatagramSocket socket to receive responce
     */
    private void AsyncReceiveRespond(DatagramSocket sock) {
        byte[] receiveData = new byte[1024];
        try {
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            sock.setSoTimeout(this.timeOutForResponce_Msec);

            sock.receive(receivePacket);

            sock.close();
            sock = null;
            final String responce = new String(receivePacket.getData(), 0, receivePacket.getLength());
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    GotResponce(responce);
                }
            });

        } catch (IOException e) {

            // final Runnable call = new Runnable() {
            // public void run() { SendDataError(e.getMessage()); }};
            //
            final String msg = e.getMessage();

            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    ResponcetError(msg);
                }
            });

            Log.e(LOG_TAG, "Receive Responce Exception", e);
            if(this.showErrorsInForm)
               form.dispatchErrorOccurredEvent(UDPClient.this, "AsyncReceiveRespond",
                    ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e.getMessage());

        } finally {
            if (sock != null) {
                sock.close();
                sock = null;
            }
        }
    }

    private void AsyncBroadcastReceiveRespond(DatagramSocket sock) {
        byte[] receiveData = new byte[1024];
        try {
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            int times = 0, times_out = 0;
            int time_out_tries = 2;
            sock.setSoTimeout(this.timeOutForResponce_Msec);
            while (times_out < time_out_tries) {

                try {
                    times++;

                    sock.receive(receivePacket);

                    final String responce = new String(receivePacket.getData(), 0, receivePacket.getLength());

                    final String remoteHost = receivePacket.getAddress().getHostAddress();
                    final int remotePort = receivePacket.getPort();

                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            GotBroadcasterResponce(remoteHost, remotePort, responce);
                        }
                    });

                } catch (IOException iOException) {
                    times_out++;
                    if (times_out >= time_out_tries) {
                        final String msg = iOException.getMessage();
                        activity.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                BroadcastResponceError(msg);
                            }
                        });
                    }

                }
            }

        } catch (IOException e) {

            // final Runnable call = new Runnable() {
            // public void run() { SendDataError(e.getMessage()); }};
            //
            final String msg = e.getMessage();

            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    ResponcetError(msg);
                }
            });

            // Log.e(LOG_TAG, "Receive Responce Exception", e);
            if(this.showErrorsInForm)
                form.dispatchErrorOccurredEvent(UDPClient.this,"AsyncReceiveRespond",
                     ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e.getMessage());
        } finally {
            if (sock != null) {
                sock.close();
                sock = null;
            }
        }
    }

    /**
     * SendBuferData to remote udp server.
     *
     * @param
     */
    @SimpleFunction(description = "Send Bufer Data in a UDP Datagram to Destination.")
    public void SendBuferData() {
        
        try {
            this.dataBuf.flush();
            byte[] sendData;
            
            sendData = this.baout.toByteArray();// toString().getBytes();
            udpSendBytes(sendData, this.HostNameOrIP, this.HostPort, false);
        } catch (IOException iOException) {
        }
        
        
    }

    /**
     * SimpleUDPSend to remote udp server.
     *
     * @param data
     * @param toHost
     * @param toPort
     */
    @SimpleFunction(description = "Simple Send A String  with UDP Datagram .")
    public void SimpleUDPSend(String data ,String toHost , int toPort ) {
        int line = 0;
        try {
             line = 875;
            try {
                String strData = new String("" + data);
                DatagramSocket socket = null;
                socket = new DatagramSocket((SocketAddress) null);
                //socket.setReuseAddress(true);
                //socket.bind(new InetSocketAddress(5005));
                
                InetAddress HostAddress = null;
                try {
                    line = 881;
                    HostAddress = InetAddress.getByName(toHost);
                } catch (UnknownHostException ex) {
                    SendDataError("1.UnknownHostException " + ex.getMessage());
                    return;
                }
                line = 887;
                DatagramPacket sendPacket = null;
                try {
                    sendPacket = null;
                    byte[] dataBytes = strData.getBytes();
                    line = 893;
                    sendPacket = new DatagramPacket(dataBytes, dataBytes.length, HostAddress, toPort);
                } catch (Exception e) {
                    SendDataError("1.2.DatagramPacket " + e.getMessage());
                    return;
                }
                
                try {
                    line = 901;
                    socket.send(sendPacket);
                } catch (IOException ex) {
                    SendDataError("2.IOException " + ex.getMessage());
                    return;
                }
                
                try {
                    socket.close();
                } catch (Exception e) {
                 line = 912;
                 SendDataError("3.socket.close; " + e.getMessage());
                }
                        
                        
            } catch (SocketException ex) {
                line = 917;
                SendDataError("4.SocketException " + ex.getMessage());
            }
            
        } catch (Exception e) {
           SendDataError("5.SocketException " + Integer.toString(line));

        }
    }
    
/**
 * 
 * @param data
 * @param toHost
 * @param toPort 
 */
  private void udpSendBytes(final byte[] data,final String toHost,final int toPort, final boolean broadcastEnable)
    {
        
        final UDPClient me =this;
        
        Thread sendThread;
        sendThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (data == null) {
                        SendDataError("1.NO DATA TO SEND");
                        return;
                    }
                    if (data.length==0) {
                        SendDataError("2.NO DATA TO SEND");
                        return;
                    }
                    
                    DatagramSocket socket = null;
                    try {
                        socket = new DatagramSocket();
                        socket.setBroadcast(broadcastEnable);
                        
                    } catch (SocketException e) {
                        // TODO Auto-generated catch block
                        Log.e(LOG_TAG, "SocketException", e);
                        if (me.showErrorsInForm) {
                            form.dispatchErrorOccurredEvent(UDPClient.this, "SendStringData",
                                    ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e.getMessage());
                        }
                        
                        SendDataError("3."+e.getMessage());
                        
                        
                        return;
                    }
                    
                    InetAddress HostAddress;
                    HostAddress = InetAddress.getByName(toHost);
                    
                    
                    DatagramPacket sendPacket = null;
                    try {
                        
                        sendPacket = new DatagramPacket(data, data.length, HostAddress, toPort);
                    } catch (Exception e) {
                        SendDataError("5."+e.getMessage());
                        return;
                    }
                    
                    
                    try {
                        socket.send(sendPacket);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        Log.e(LOG_TAG, "IOException", e);
                        if (me.showErrorsInForm) {
                            form.dispatchErrorOccurredEvent(UDPClient.this, "SendStringData", ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, toHost);
                        }
                        
                        SendDataError("6.Exception :" +e.getMessage());
                        
                        socket.close();
                        return;
                    }
                    
                    if(broadcastEnable && me.want_BroadcastResponce){
                        final DatagramSocket AsyncSocket = socket;
                        AsynchUtil.runAsynchronously(new Runnable() {
                            @Override
                            public void run() {
                                AsyncBroadcastReceiveRespond(AsyncSocket);
                            }
                        });
                    }
                    else
                        if (!broadcastEnable && me.want_Responce) {
                            final DatagramSocket AsyncSocket = socket;
                            AsynchUtil.runAsynchronously(new Runnable() {
                                @Override
                                public void run() {
                                    AsyncReceiveRespond(AsyncSocket);
                                }
                            });
                        }
                } catch (Exception e) {
                    SendDataError("7.ExceptionX :" +  " . Type:"+e.getClass().getCanonicalName());
                }
                
            }
        }
        );
        sendThread.start();
    }
            
    
    /**
     * 
     * @param data
     * @param toHost
     * @param toPort 
     */
    void threadSendStringData(final String data,final String toHost,final int toPort)
    {
       final UDPClient me =this;
        
        Thread sendThread = new Thread(new Runnable() {
            @Override
            public void run() {
        try { 
        if (data == null) {
                SendDataError("1.DATA TO SEND IS Null");
                return;
            }
            if (data.equals("")) {
                SendDataError("2.NO DATA TO SEND Is Empty");
                return;
            }
            
            DatagramSocket socket = null;
            try {
                socket = new DatagramSocket();
            } catch (SocketException e) {
                // TODO Auto-generated catch block
                Log.e(LOG_TAG, "SocketException", e);
                if (me.showErrorsInForm) {
                    form.dispatchErrorOccurredEvent(UDPClient.this, "SendStringData",
                            ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e.getMessage());
                }
                
                SendDataError("3."+e.getMessage());
                
                
                return;
            }
            
            InetAddress HostAddress;
            HostAddress = InetAddress.getByName(me.HostNameOrIP);


            DatagramPacket sendPacket = null;
            byte[] sendData = new byte[1024];
            try {
                sendData = data.getBytes();
                
                sendPacket = new DatagramPacket(sendData, sendData.length, HostAddress, me.HostPort);
            } catch (Exception e) {
                SendDataError("5."+e.getMessage());
                return;
            }
            
            
            try {
                socket.send(sendPacket);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                Log.e(LOG_TAG, "IOException", e);
                if (me.showErrorsInForm) {
                    form.dispatchErrorOccurredEvent(UDPClient.this, "SendStringData", ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, me.HostNameOrIP);
                }
                
                SendDataError("6.Exception :" +e.getMessage());
                
                socket.close();
                return;
            }
            
            if (me.want_Responce) {
                final DatagramSocket AsyncSocket = socket;
                AsynchUtil.runAsynchronously(new Runnable() {
                    @Override
                    public void run() {
                        AsyncReceiveRespond(AsyncSocket);
                    }
                });
            }
        } catch (Exception e) {
            SendDataError("7.ExceptionX :" +  " . Type:"+e.getClass().getCanonicalName());
        }
        
                   }
        }
        );
        sendThread.start();
//        try {
//            sendThread.join();
//        } catch (InterruptedException ex) {
//            Logger.getLogger(UDPClient.class.getName()).log(Level.SEVERE, null, ex);
//        }
 
    }
    
    
    /**
     * SendStringData to remote udp server.
     *
     * @param data
     */
    @SimpleFunction(description = "Send A String Data with UDP Datagram to Destination.")
    public void SendStringData(String data) {

        //threadSendStringData(data,this.HostNameOrIP,this.HostPort);
        udpSendBytes(data.getBytes(),this.HostNameOrIP,this.HostPort,false);
    }
    

    /**
     * BroadcastBuferData .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "Broadcast Buffer Data with UDP Datagram to Destination.")
    public void BroadcastBuferData() {

        try {
            this.dataBuf.flush();
            byte[] sendData;
            
            sendData = this.baout.toByteArray();// toString().getBytes();
            udpSendBytes(sendData, this.broadcastIP, this.HostPort, true);
        } catch (IOException iOException) {
        }

    }

    // -----------------------------------------------------------------------------------
    /**
     * BroadcastBuferData .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "Broadcast Bufer Data with UDP Datagram to Destination.")
    public void BroadcastStringData(String data) {

        
        //threadSendStringData(data,this.HostNameOrIP,this.HostPort);
        udpSendBytes(data.getBytes(),this.broadcastIP,this.HostPort,true);

    }

    // -----------------------------------------------------------------------------------
    /**
     * CloseUDPSesion .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "Close UDP Sesion.")
    public void CloseUDPSesion() {
        if (udpSockSession == null) {
            this.sesionStatus = NO_SESION;
            UDPSessionStatusChanged("NO_SESION to close");
            return;
        }
        this.sesionStatus = SESION_TO_CLOSE;
        synchronized (udpSockSession) {

            while (((sesionStatus != NO_SESION) && (sesionStatus != SESION_CLOSED))) {
                try {
                    udpSockSession.wait(1000);// Thread.sleep(10);
                } catch (InterruptedException e) {
                    // e.printStackTrace();
                }
            }
            this.sesionStatus = NO_SESION;
            UDPSessionStatusChanged("NO_SESION");
            // notify();
        }
        udpSockSession = null;
    }

    /**
     * BroadcastBuferData .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "Send Bufer Data in a UDP Datagram to Destination over UDP Session")
    public void UDPSesionSendBuffer() {

        // synchronized (udpSockSession) { //(udpSockSession == null) ||
        if (this.dataBuf == null) {
            SendDataError("NO DATA TO SEND");
            return;
        }

        if ((this.sesionStatus != SESION_OPENED)) {
            Log.e(LOG_TAG, "NO UDP SESSION TO SEND BUFFER");

            SendDataError("NO UDP SESSION TO SEND BUFFER");
            return;

        }

        if (udpSockSession == null) {
            SendDataError("Null UDP Socket");
            return;
        }

        try {
            this.dataBuf.flush();
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            Log.e(LOG_TAG, "IOException", e1);
            if(this.showErrorsInForm)
                form.dispatchErrorOccurredEvent(UDPClient.this, "SendBuferData",
                   ErrorMessages.ERROR_NXT_ERROR_CODE_RECEIVED, e1.getMessage());
            SendDataError(e1.getMessage());

            // e1.printStackTrace();
            return;
        }

        if (this.baout.size() == 0) {
            SendDataError("NO DATA TO SEND");
            return;
        }

        byte[] sendData = new byte[1024];

        sendData = this.baout.toByteArray();// toString().getBytes();
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, SessionHostAddress, SessionHostPort);

        synchronized (sessionThread) {

            while (session_action != SESION_ACCEPT_SEND) {
                try {
                    Thread.sleep(10); // wait(100);
                } catch (InterruptedException e) {
                }
            }
            try {
                udpSockSession.send(sendPacket);
                session_action = SESION_WAIT_RECEIVE;
            } catch (IOException e1) {
                this.sesionStatus = SESION_ERROR;

                SendDataError("SESION_ERROR : " + e1.getMessage());
                sessionThread.notifyAll();

                CloseUDPSesion();

                return;
            }

            try {

                sessionThread.notify();
            } catch (java.lang.IllegalMonitorStateException e) {
                SendDataError("NOTIFY error ->" + e.getMessage());
            }
        }

    }

    /**
     * UDPSesionSendStringData .
     *
     * @param String data
     *
     */
    @SimpleFunction(description = "Send String Data in a UDP Datagram to Destination over UDP Sessio")
    public void UDPSesionSendStringData(String data) {

        if ((this.sesionStatus != SESION_OPENED)) {
            Log.e(LOG_TAG, "NO UDP SESSION ");

            SendDataError("NO UDP SESSION TO SEND STRING");
            return;
        }

        if (udpSockSession == null) {
            SendDataError("Null UDP Socket");
            return;
        }

        if (data == null) {
            SendDataError("NO DATA TO SEND");
            return;
        }
        if (data.equals("")) {
            SendDataError("NO DATA TO SEND");
            return;
        }

        byte[] sendData = data.getBytes();// new byte[1024];

        // sendData = data.getBytes();
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, SessionHostAddress, SessionHostPort);

        UDPSessionErrorOccured("SESION_WANT_SEND ");

        if (session_action == SESION_WAIT_RECEIVE) {
            session_action = SESION_WANT_SEND;
        }

        synchronized (sessionThread) {

            while (session_action != SESION_ACCEPT_SEND) {
                try {
                    Thread.sleep(10); // wait(100);
                } catch (InterruptedException e) {
                }
            }
            try {
                udpSockSession.send(sendPacket);
                session_action = SESION_WAIT_RECEIVE;
            } catch (IOException e1) {
                this.sesionStatus = SESION_ERROR;

                SendDataError("SESION_ERROR : " + e1.getMessage());
                sessionThread.notifyAll();

                CloseUDPSesion();

                return;
            }

            try {

                sessionThread.notify();
            } catch (java.lang.IllegalMonitorStateException e) {
                SendDataError("NOTIFY error ->" + e.getMessage());
            }
        }

    }

    /**
     * BroadcastBuferData .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "Broadcast Bufer Data with UDP Datagram to Destination.")
    public int UDPSesionLocalPort() {
        if (udpSockSession == null || (this.sesionStatus != SESION_OPENED)) {
            Log.e(LOG_TAG, "NO VALID UDP SESSION");

            SendDataError("NO VALID UDP SESSION");
            return -1;
        }

        return this.udpSockSession.getLocalPort();

    }

    /**
     * BroadcastBuferData .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "UDP Sesion Local Address")
    public String UDPSesionLocalAddress() {
        if (udpSockSession == null || (this.sesionStatus != SESION_OPENED)) {
            Log.e(LOG_TAG, "NO VALID UDP SESSION");

            SendDataError("NO VALID UDP SESSION");
            return "";
        }

        return this.udpSockSession.getLocalAddress().toString();

    }

    /**
     * BroadcastBuferData .
     *
     * @param String BroadcastIP
     */
    @SimpleFunction(description = "Create UDP Sesion. A dialogue over UDP.")
    public void CreateUDPSesion() {

        if (udpSockSession != null || ((this.sesionStatus != NO_SESION) && (this.sesionStatus != SESION_CLOSED))) {
            Log.e(LOG_TAG, "UDP SESSION ALREADY OPENED");

            SendDataError("UDP SESSION ALREADY OPENED");
            return;

        }

        session_action = SESION_WAIT_RECEIVE;
        UDPSessionStatusChanged("SESION_INITIALIZE");

        try {
            SessionHostAddress = InetAddress.getByName(this.HostNameOrIP);
            SessionHostPort = this.HostPort;

        } catch (UnknownHostException e) {
            udpSockSession = null;
            Log.e(LOG_TAG, "UnknownHostException", e);
            if(this.showErrorsInForm)
                form.dispatchErrorOccurredEvent(UDPClient.this, "CreateUDPSesion", e.hashCode(), this.HostNameOrIP);
            SendDataError(e.getMessage());
            this.sesionStatus = NO_SESION;

            return;
        }

        try {
            udpSockSession = new DatagramSocket();

        } catch (SocketException e) {
            Log.e(LOG_TAG, "SocketException", e);
            if(this.showErrorsInForm)
                form.dispatchErrorOccurredEvent(UDPClient.this, "SendStringData",
                    e.hashCode(), udpSockSession);
            SendDataError(e.getMessage());
            this.sesionStatus = NO_SESION;
            return;
        }

        udpSockSession.connect(SessionHostAddress, SessionHostPort);

        this.sesionStatus = SESION_OPENED;

        UDPSessionStatusChanged("SESION_OPENED");
        // sessionThread = new Thread();

        AsynchUtil.runAsynchronously(new Runnable() {
            @Override
            public void run() {

                sessionThread = Thread.currentThread();
                int timeOut = 200;// timeOutForResponce_Msec;

                boolean receiveContinue = true;

                try {
                    udpSockSession.setSoTimeout(timeOut);
                } catch (SocketException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                long countwait = 0;
                byte[] receiveData = new byte[1024];
                while (sesionStatus == SESION_OPENED && receiveContinue && udpSockSession.isClosed() == false) {
                    countwait++;
                    final long cw = countwait;

                    if (session_action == SESION_WANT_SEND) {
                        session_action = SESION_ACCEPT_SEND;
                    }

                    synchronized (sessionThread) {

                        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

                        try {
                            if (session_action == SESION_ACCEPT_SEND) {

                                // synchronized (this) {
                                while ((session_action != SESION_WAIT_RECEIVE) && (sesionStatus == SESION_OPENED)) {

                                    sessionThread.wait(200);
                                }
                            } else if (session_action == SESION_WAIT_RECEIVE) {
                                udpSockSession.receive(receivePacket);

                                final String responce = new String(receivePacket.getData(), 0,
                                        receivePacket.getLength());
                                //final byte[] responseAsBytes = receivePacket.getData().clone();
                                activity.runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        GotUDPSessionResponce(responce);//,responseAsBytes);
                                    }
                                });
                            }

                        } catch (SocketTimeoutException e) {
                            // e.printStackTrace();

                            continue;

                        } catch (IOException e) {
                            // e.printStackTrace();
                            receiveContinue = false;
                            sesionStatus = SESION_ERROR;
                            activity.runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    UDPSessionStatusChanged("SESION_ERROR");
                                }
                            });

                        } catch (InterruptedException e) {

                            // e.printStackTrace();
                        }

                    } // synchronized block end

                }

                if (udpSockSession != null) {
                    synchronized (udpSockSession) {

                        udpSockSession.disconnect();
                        udpSockSession.close();
                        sesionStatus = SESION_CLOSED;
                        udpSockSession.notify();
                    }

                    // udpSockSession = null and NO_SESION by main Thread
                    sesionStatus = SESION_CLOSED;

                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            UDPSessionStatusChanged("SESION_CLOSED");
                        }
                    });

                }
            }

        });

    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Error Occured on UDP Session.")
    public void UDPSessionErrorOccured(String errmsg) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "UDPSessionErrorOccured", errmsg);
    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating that the contents from the file have been read.")
    public void GotUDPSessionResponce(String Responce)//,byte[] BytesResponce) 
    {
        // invoke the application's "GotText" event handler.
//        Byte[] retBytes = new Byte[BytesResponce.length];
//        for(int i=0;i<BytesResponce.length;i++)
//                retBytes[i]= BytesResponce[i];
        EventDispatcher.dispatchEvent(this, "GotUDPSessionResponce", Responce) ; //,YailList.makeList(retBytes));
    }

    /**
     * Event indicating that a request has finished.
     *
     * @param text read from the file
     */
    @SimpleEvent(description = "Event indicating that the contents from the file have been read.")
    public void UDPSessionStatusChanged(String status) {
        // invoke the application's "GotText" event handler.
        EventDispatcher.dispatchEvent(this, "UDPSessionStatusChanged", status);
    }
    



}
