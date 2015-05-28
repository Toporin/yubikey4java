/*
 * Java code to talk to YubiKeys
 * Loosely based on python-yubico (https://github.com/Yubico/python-yubico)
 * Only partial support (mainly HMAC-SHA1 challenge-response)
 * 
 * (c) 2015 by Toporin - 1P7kS1SX2ETDD2Sgyk51BKWUo7YXME928V
 * Sources available on https://github.com/Toporin
 * 
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *******************************************************************************   
 */ 

package org.toporin.yubikey4java;

//import java.io.BufferedReader;
//import java.io.IOException;
//import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;
import org.usb4java.DeviceHandle;
import org.usb4java.DeviceList;
import org.usb4java.LibUsb;
import org.usb4java.LibUsbException;

//import java.util.concurrent.TimeUnit;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
//import java.util.logging.Level;
//import java.util.logging.Logger;

/**
 * Controls a USB Yubikey
 * 
 * Based on the MissileLauncher examples from the Usb4Java project
 * @author Klaus Reimer <k@ailis.de>
 */
public class YubikeyConnector
{
    private static final boolean DEBUG=true;
    
    /** The vendor ID of the Yubikey. */
    private static final short VENDOR_ID = 0x1050;
    
    /** The product ID of the Yubikey. */
    //private static final short PRODUCT_ID = 0x0114;
    //private static final short PRODUCT_ID2 = 0x0111;
    private static final short[] PRODUCT_ID_NEO = {0x0111, 0x0114};
    
    // Various USB/HID parameters from yubikey_usb_hid.py
    private static final byte _USB_TYPE_CLASS         = (0x01 << 5);
    private static final byte _USB_RECIP_INTERFACE    = 0x01;
    private static final byte _USB_ENDPOINT_IN        = (byte)0x80;
    private static final byte _USB_ENDPOINT_OUT       = 0x00;

    private static final byte _HID_GET_REPORT         = 0x01;
    private static final byte _HID_SET_REPORT         = 0x09;

    private static final int _USB_TIMEOUT_MS         = 2000;

    // from ykcore_backend.h
    private static final byte _FEATURE_RPT_SIZE       = 8;
    private static final short _REPORT_TYPE_FEATURE    = 0x03;    
    
    // yubikey_defs.py
    public static final byte RESP_TIMEOUT_WAIT_MASK= 0x1f; // Mask to get timeout value
    public static final byte RESP_TIMEOUT_WAIT_FLAG= 0x20; // Waiting for timeout operation - seconds left in lower 5 bits
    public static final byte RESP_PENDING_FLAG	=    0x40; // Response pending flag
    public static final byte SLOT_WRITE_FLAG=  (byte)0x80; // Write flag - set by app - cleared by device

    public static final byte SHA1_MAX_BLOCK_SIZE=   64;   // Max size of input SHA1 block
    public static final byte SHA1_DIGEST_SIZE=      20;   // Size of SHA1 digest = 160 bits
    
    private static final byte MODE_AND=0;
    private static final byte MODE_NAND=1;
    private static final byte MODE_HMAC=0;
    private static final int SLOT_1=1;
    private static final int SLOT_2=2;
     
    /**
     * Searches for the yubikey device and returns it. If there are
     * multiple yubikeys attached then this simple demo only returns
     * the first one.
     * 
     * @return The yubikey USB device or null if not found.
     */
    public static Device findYubikey(short[] pids){
        // Read the USB device list
        DeviceList list = new DeviceList();
        int result = LibUsb.getDeviceList(null, list);
        if (result < 0){
            throw new RuntimeException("Unable to get device list. Result=" + result);
        }

        try{
            // Iterate over all devices and scan for the missile launcher
            for (Device device: list){
                DeviceDescriptor descriptor = new DeviceDescriptor();
                result = LibUsb.getDeviceDescriptor(device, descriptor);
                debug(descriptor.dump());
                
                if (result < 0){
                    throw new RuntimeException("Unable to read device descriptor. Result=" + result);
                }
                if (descriptor.idVendor() == VENDOR_ID && contains(pids, descriptor.idProduct())) {
                    debug("Found device:"+device.toString());
                    return device;
                }
            }
        }
        finally{
            // Ensure the allocated device list is freed
            //LibUsb.freeDeviceList(list, true);
            LibUsb.freeDeviceList(list, false);
        }

        // No yubikey found
        return null;
    }
    
    public static boolean contains(short[] pids, short pid){
        for (int i=0; i<pids.length; i++){
            if (pids[i]==pid)
                return true;
        }
        return false;    
    }
    
    public static byte[] challenge_response(DeviceHandle handle, byte[] challenge, byte mode, int slot, boolean variable, boolean may_block){
        //""" Do challenge-response with a YubiKey > 2.0. """
        // Check length and pad challenge if appropriate
        byte[] payload= new byte[SHA1_MAX_BLOCK_SIZE];
        int response_len;
        if (mode == MODE_HMAC){
            if (challenge.length > SHA1_MAX_BLOCK_SIZE){
                throw new YubikeyException("Unsupported challenge size");
            }
            else if (challenge.length < SHA1_MAX_BLOCK_SIZE){
                byte pad_with = 0x00;
                if (variable & challenge[challenge.length-1]==pad_with)
                    pad_with = (byte)0xff;
                java.util.Arrays.fill(payload, pad_with);
                System.arraycopy(challenge, 0, payload, 0, challenge.length);
            }
            else{
                System.arraycopy(challenge, 0, payload, 0, SHA1_MAX_BLOCK_SIZE);
            }
            response_len = SHA1_DIGEST_SIZE;
        }
        else{
            throw new YubikeyException("Unsupported challenge mode:"+mode);
        }
        
        if (slot!=1 && slot!=2)
            throw new YubikeyException("Unsupported challenge slot:"+slot);
        
        Frame frame = new Frame(payload, slot);
        write(handle, frame);
        byte[] response = read_response(handle, may_block);
        if (!YubikeyUtil.validate_crc16(response, 0, response_len+2))
            throw new YubikeyException("Read from device failed CRC check");
        
        return Arrays.copyOf(response, response_len);
    }
    
    public static boolean write(DeviceHandle handle, Frame frame){
        List<byte[]> reports= frame.getByteArray();
        for (int i=0; i<reports.size(); i++){
            debug("Reports["+i+"]:"+YubikeyUtil.toHexString(reports.get(i)));
            // first, we ensure the YubiKey will accept a write
            waitforClear(handle, SLOT_WRITE_FLAG, false);
            raw_write(handle, reports.get(i));
        }
        return true;
    }
    
    public static boolean write_reset(DeviceHandle handle){
        byte[] data = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,(byte)0x8f};
        raw_write(handle, data);
        waitforClear(handle, SLOT_WRITE_FLAG, false);
        return true;
    }
    
    /**
     * Sends a message to the yubikey.
     * 
     * @param handle
     *            The USB device handle.
     * @param message
     *            The message to send.
     */
    public static int raw_write(DeviceHandle handle, byte[] message)
    {
        ByteBuffer buffer = ByteBuffer.allocateDirect(message.length);
        buffer.put(message);
        buffer.rewind();
        int transfered = LibUsb.controlTransfer(handle,
            (byte) (LibUsb.REQUEST_TYPE_CLASS | LibUsb.RECIPIENT_INTERFACE | _USB_ENDPOINT_OUT),
            _HID_SET_REPORT,
            (short)(_REPORT_TYPE_FEATURE << 8),//(short) 2,
            (short) 1, buffer, _USB_TIMEOUT_MS);
        
        if (transfered < 0)
            throw new LibUsbException("Control transfer failed", transfered);
        if (transfered != message.length)
            throw new RuntimeException("Not all data was sent to device");
        
        debug("Data sent to device: "+YubikeyUtil.toHexString(message));
        return transfered;
    }
    
    public static byte[] read_response(DeviceHandle handle, boolean may_block){
        //""" Wait for a response to become available, and read it. """
        // wait for response to become available
        ByteBuffer buff= ByteBuffer.allocate(48);
        byte[] res = waitforSet(handle, RESP_PENDING_FLAG, may_block);
        buff.put(res, 0, 7);        
        // continue reading while response pending is set
        while (true){
            res = read(handle);
            byte flags = res[7];
            if ((flags & RESP_PENDING_FLAG)!=0){
                byte seq = (byte)(flags & RESP_TIMEOUT_WAIT_MASK);
                if (seq == 0)
                    break;
                buff.put(res, 0, 7);
            }
            else{
                break;
            }
        }
        write_reset(handle);
        return buff.array();
    }
    
    public static byte[] read(DeviceHandle handle)
    {
        ByteBuffer buffer = ByteBuffer.allocateDirect(_FEATURE_RPT_SIZE);
        buffer.rewind();
        int transfered = LibUsb.controlTransfer(handle,
            (byte) (LibUsb.REQUEST_TYPE_CLASS | LibUsb.RECIPIENT_INTERFACE | _USB_ENDPOINT_IN),
            _HID_GET_REPORT,
            (short)(_REPORT_TYPE_FEATURE << 8),//(short) 2,
            (short) 1, buffer, _USB_TIMEOUT_MS);
        
        if (transfered < 0)
            throw new LibUsbException("Control transfer failed", transfered);
        if (transfered != _FEATURE_RPT_SIZE)
            throw new RuntimeException("Not all data was received from device:"+transfered);
        
        byte[] data= new byte[_FEATURE_RPT_SIZE];
        buffer.rewind();
        for (int i=0; i<_FEATURE_RPT_SIZE; i++){
            data[i]= buffer.get();
        }
        debug("Data received from device: "+YubikeyUtil.toHexString(data));
        return data;
        
    }
    
    public static byte[] waitforClear(DeviceHandle handle, byte mask, boolean may_block){
        return waitfor(handle, MODE_NAND, mask, may_block, 2);
    }
    public static byte[] waitforSet(DeviceHandle handle, byte mask, boolean may_block){
        return waitfor(handle, MODE_AND, mask, may_block, 2);
    }    
    public static byte[] waitfor(DeviceHandle handle, byte mode, byte mask, boolean may_block, int timeout){
        
        boolean finished = false;
        int sleep = 10; // in millisecond
        // After six sleeps, we've slept 0.64 seconds.
        int wait_num = (timeout * 2) - 1 + 6;
        boolean resp_timeout = false;    // YubiKey hasn't indicated RESP_TIMEOUT (yet)
        
        byte[] data= new byte[_FEATURE_RPT_SIZE];        
        while (!finished){
            data = read(handle);
            byte flags = data[7];

            if ((flags & RESP_TIMEOUT_WAIT_FLAG)!=0){
                if (!resp_timeout){
                    resp_timeout = true;
                    int seconds_left = (flags & RESP_TIMEOUT_WAIT_MASK);
                    debug("Device indicates RESP_TIMEOUT "+seconds_left);
                    if (may_block){
                        // calculate new wait_num - never more than 20 seconds
                        seconds_left = Math.min(20, seconds_left);
                        wait_num = (seconds_left * 2) - 1 + 6;
                    }
                }
            }
            
            if (mode==MODE_NAND){
                if (!((flags & mask)==mask))
                    finished = true;
                else
                    debug("Status "+YubikeyUtil.toHexString(flags)+" has not cleared bits "+YubikeyUtil.toHexString(mask));
            }
            else if (mode==MODE_AND){
                if ((flags & mask) == mask)
                    finished = true;
                else
                    debug("Status "+YubikeyUtil.toHexString(flags)+" has not sets bits "+YubikeyUtil.toHexString(mask));
            }
            
            if (!finished){
                wait_num -= 1;
                if (wait_num == 0){
                    String reason;    
                    if (mode == MODE_NAND)
                        throw new YubikeyException("Timed out waiting for YubiKey to clear status"+YubikeyUtil.toHexString(mask));
                    else
                        throw new YubikeyException("Timed out waiting for YubiKey to set status"+YubikeyUtil.toHexString(mask));
                    
                }
                try {
                    MILLISECONDS.sleep(sleep);
                } catch (InterruptedException ex) {
                    
                }
                sleep = Math.min(sleep + sleep, 500);
            }
            else
                return data;
            }
        return data;
    }
    
    public static void debug(String msg){
        if (DEBUG)
            System.out.println(msg);
    }
    
    public static void main(String[] args)
    {
        // Initialize the libusb context
        int result = LibUsb.init(null);
        if (result != LibUsb.SUCCESS){
            throw new LibUsbException("Unable to initialize libusb", result);
        }

        // Search for the missile launcher USB device and stop when not found
        Device device = findYubikey(PRODUCT_ID_NEO);
        if (device == null){
            System.err.println("Yubikey not found.");
            System.exit(1);
        }

        // Open the device
        DeviceHandle handle = new DeviceHandle();
        result = LibUsb.open(device, handle);
        if (result != LibUsb.SUCCESS){
            throw new LibUsbException("Unable to open USB device", result);
        }
        try{
            // Check if kernel driver is attached to the interface
            int attached = LibUsb.kernelDriverActive(handle, _USB_RECIP_INTERFACE);
            if (attached < 0 && attached!=LibUsb.ERROR_NOT_SUPPORTED){   
                //debug("Attach error (not supported on Windows?):"+attached);
                throw new LibUsbException("Unable to check kernel driver active", result);
            }

            // Detach kernel driver from interface 0 and 1. This can fail if
            // kernel is not attached to the device or operating system
            // doesn't support this operation. These cases are ignored here.
            result = LibUsb.detachKernelDriver(handle, _USB_RECIP_INTERFACE);
            if (result != LibUsb.SUCCESS &&
                result != LibUsb.ERROR_NOT_SUPPORTED &&
                result != LibUsb.ERROR_NOT_FOUND)
            {
                throw new LibUsbException("Unable to detach kernel driver", result);
            }
            
            // Claim interface
            result = LibUsb.claimInterface(handle, _USB_RECIP_INTERFACE);
            if (result != LibUsb.SUCCESS){
                throw new LibUsbException("Unable to claim interface", result);
            }
            System.out.println("claimInterface:"+result);
            
            // manual challenge-response
            // sends frame...
            byte[] frame0= {(byte)0x53, (byte)0x61, (byte)0x6D, (byte)0x70, (byte)0x6C, (byte)0x65, (byte)0x20, (byte)0x80};
            byte[] frame1= {(byte)0x23, (byte)0x32, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x81};
            byte[] frame2= {(byte)0x00, (byte)0x38, (byte)0xF8, (byte)0x2A, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x89};
            raw_write(handle, frame0);
            raw_write(handle, frame1);
            raw_write(handle, frame2);
            // recover & verify hmac+crc
            byte[] response=read_response(handle, true);
            System.out.println("Challenge response:"+YubikeyUtil.toHexString(response));
            byte[] hmac= Arrays.copyOf(response, SHA1_DIGEST_SIZE+2);
            System.out.println("validate_crc16:"+YubikeyUtil.validate_crc16(hmac));
            
            // Challenge-response 
            byte[] challenge= {(byte)0x53, (byte)0x61, (byte)0x6D, (byte)0x70, (byte)0x6C, (byte)0x65, (byte)0x20, (byte)0x23, (byte)0x32};
            response= challenge_response(handle, challenge, MODE_HMAC, SLOT_2, false, true);
            System.out.println("HMAC:"+YubikeyUtil.toHexString(response));
            
            // Release the interface
            result = LibUsb.releaseInterface(handle, _USB_RECIP_INTERFACE);
            if (result != LibUsb.SUCCESS){
                debug("releaseInterface():"+result);
                throw new LibUsbException("Unable to release interface", result);
            }

            // Re-attach kernel driver if needed
            if (attached == 1){
                LibUsb.attachKernelDriver(handle, _USB_RECIP_INTERFACE);
                if (result != LibUsb.SUCCESS){
                    throw new LibUsbException("Unable to re-attach kernel driver", result);
                }
            }

            System.out.println("Exiting");
        }
        finally{
            LibUsb.close(handle);
        }

        // Deinitialize the libusb context
        LibUsb.exit(null);
    }
    
    public static class YubikeyException extends RuntimeException {
        YubikeyException(String msg){
            super(msg);
        }
    }
    
    
}