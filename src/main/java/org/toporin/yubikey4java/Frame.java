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


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Frame{
        
        public static final byte[] NULLBYTES= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        public static final int SLOT_DATA_SIZE=64;
        public static final byte SLOT_CHAL_HMAC1=0x30;	/* Write 64 byte challenge to slot 1, get HMAC-SHA1 response */
        public static final byte SLOT_CHAL_HMAC2=0x38;	/* Write 64 byte challenge to slot 2, get HMAC-SHA1 response */
    
        public byte[] payload;
        public byte slot;
        public short crc;
        public byte[] filler;
        
        
        public Frame(){
            payload= new byte[SLOT_DATA_SIZE];
            filler= new byte[3];
        }
        
        public Frame(byte[] load, int slot){
            this.payload= Arrays.copyOf(load, SLOT_DATA_SIZE);
            filler= new byte[3];
            setSlot(slot);
            setCRC();
        }
        
//        public Frame(byte[] chal, boolean isVariable, int slot){
//            payload= new byte[SLOT_DATA_SIZE];
//            filler= new byte[3];
//            setChallenge(chal, isVariable);
//            setSlot(slot);
//            setCRC();
//        }
//        
//        public void setChallenge(byte[] chal, boolean isVariable){
//            
//            if (chal.length==SLOT_DATA_SIZE){
//                System.arraycopy(chal, 0, payload, 0, SLOT_DATA_SIZE);
//            }
//            else if (chal.length<SLOT_DATA_SIZE){
//                byte pad_with = 0x00;
//                if (isVariable & chal[chal.length-1]==pad_with)
//                    pad_with = (byte)0xff;
//                java.util.Arrays.fill(payload, pad_with);
//                System.arraycopy(chal, 0, payload, 0, chal.length);
//            }
//        }
//        
        public void setSlot(int slotnbr){
            slot= (slotnbr==1)?SLOT_CHAL_HMAC1:SLOT_CHAL_HMAC2;
        }
        
        public void setCRC(){
            
            crc= YubikeyUtil.crc16(payload);
            
            //Util.crc16(payload, byte[] dst, int dstOff);
//            int POLYNOMIAL   = 0x8408;
//            int PRESET_VALUE = 0xFFFF;
//
//            int current_crc_value = PRESET_VALUE;
//            for (int i = 0; i < payload.length; i++ ){
//                current_crc_value ^= payload[i] & 0xFF;
//                for (int j = 0; j < 8; j++){
//                  if ((current_crc_value & 1) != 0)
//                    current_crc_value = (current_crc_value >>> 1) ^ POLYNOMIAL;
//                  else
//                    current_crc_value = current_crc_value >>> 1;
//                }
//            }
//            current_crc_value = ~current_crc_value;
//            crc= (short)(current_crc_value & 0xFFFF);
//            
//            byte[] ba= new byte[2];
//            ba[0]= (byte)(crc&0xff);
//            ba[1]= (byte)((crc>>8)&0xff);
            //System.out.println("CRC="+crc+" crchex:"+org.satochip.satochipclient.SatoChipClient.toString(ba));
        }
        
        public List<byte[]> getByteArray(){
            
            List<byte[]> frameList = new ArrayList<byte[]>();
            byte[] tmpBytes= new byte[7];
            byte[] frameBytes= new byte[8];
            byte seq=0;
            
            // first frame
            System.arraycopy(payload, 0, frameBytes, 0, 7);
            frameBytes[7]= (byte)(YubikeyConnector.SLOT_WRITE_FLAG | seq);
            frameList.add(frameBytes);
            seq++;
            
            // payload
            for (seq=1; seq<9; seq++){
                
                System.arraycopy(payload, seq*7, tmpBytes, 0, 7);
                if (!java.util.Arrays.equals(tmpBytes, NULLBYTES)){
                    frameBytes= new byte[8];
                    System.arraycopy(payload, seq*7, frameBytes, 0, 7);
                    frameBytes[7]= (byte)(YubikeyConnector.SLOT_WRITE_FLAG | seq);
                    frameList.add(frameBytes);
                }
            }
            
            // last byte of payload+ slot+crc+filler
            setCRC();
            frameBytes= new byte[8];
            System.out.println("crc:"+crc+" "+(byte)(crc & 0xff)+" "+((crc>>8) & 0xff));
            
            seq=9;
            frameBytes[0]= payload[63];
            frameBytes[1]= slot;
            frameBytes[2]= (byte)(crc & 0xff); //lsb
            frameBytes[3]= (byte)((crc>>8) & 0xff); //msb
            frameBytes[4]= 0x00;
            frameBytes[5]= 0x00;
            frameBytes[6]= 0x00;
            frameBytes[7]= (byte)(YubikeyConnector.SLOT_WRITE_FLAG | seq);
            frameList.add(frameBytes);
            
            return frameList;
        }
        
        
        
    }    