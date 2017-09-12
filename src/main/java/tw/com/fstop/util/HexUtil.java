
/*
 * Copyright (c) 2017, FSTOP, Inc. All Rights Reserved.
 *
 * You may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tw.com.fstop.util;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Class for dump binary data and byte array operation.
 * 
 * Supports ASCII and EBCDIC encoding.
 *
 * @since 1.0.0
 */
public class HexUtil
{
    
    /**
     * byte order convert
     * AE41 5652       high byte first      high word first  = 0  (預設值)
     * 5652 AE41       high byte first      low word first   = 1
     * 41AE 5256       low byte first      high word first   = 2
     * 5256 41AE       low byte first      low word first    = 3
     * @param data
     * @param order
     * @return
     */
    public static byte [] byteOrder(byte [] data, int order)
    {
        byte [] ret = null; //new byte [data.length];
        
        ret = Arrays.copyOf(data, data.length);
        
        if (order == 0)  //high byte first      high word first
        {
            return ret;
        }
        else if (order == 1) //high byte first      low word first
        {
            //word swap 0,1 -> 2,3
            //AE41 5652 -> 5652 AE41
            for(int i = 0; ret.length >= 4 && i < ret.length;)
            {
                //low word first
                ret[i] = data[i + 2];
                ret[i+1] = data[i + 3];
                
                ret[i + 2] = data[i];
                ret[i + 3] = data[i + 1];
                i = i + 4;
            }
        }
        else if (order == 2) //low byte first      high word first
        {
            //byte swap 0,1 -> 2,3
            //AE41 5652 -> 41AE 5256
            for(int i = 0; ret.length >= 2 && i < ret.length;)
            {
                ret[i + 1] = data[i];
                ret[i] = data[i + 1];
                i = i + 2;
            }           
        }
        else if (order == 3) //low byte first      low word first
        {
            //word & byte swap 0,1 -> 2,3
            //AE41 5652 -> 5256 41AE
            for(int i = 0; ret.length >= 4 && i < ret.length;)
            {
                //low word first, low byte first
                ret[i] = data[i + 3];
                ret[i+1] = data[i + 2];
                
                ret[i + 2] = data[i + 1];
                ret[i + 3] = data[i];
                i = i + 4;
            }           
        }
        
        return ret;
    }

    /**
     * Convert float to byte array.
     * LITTLE_ENDIAN
     * @param f float value
     * @return byte array of IEEE 754 floating-point single-format bit layout
     */
    public static final byte [] floatToByteArray(float f)
    {
        //The initial order of a byte buffer is always BIG_ENDIAN.
        ByteBuffer bbuf = ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        bbuf.putFloat(0, f);
        
        byte [] b = null;
        
        //IEEE 754 floating-point single-format bit layout
        if (bbuf.hasArray())
        {
            b = bbuf.array();            
        }

//LITTLE_ENDIAN        
//IEEE 754 floating-point single-format bit layout        
//        int bits = Float.floatToIntBits(f);
//        byte[] bytes = new byte[4];
//        bytes[0] = (byte)(bits & 0xff);
//        bytes[1] = (byte)((bits >> 8) & 0xff);
//        bytes[2] = (byte)((bits >> 16) & 0xff);
//        bytes[3] = (byte)((bits >> 24) & 0xff);
//        b = bytes;
        
        return b;
    }
    
    /**
     * Convert int to byte array.
     * LITTLE_ENDIAN
     * 將 int 數值轉成 byte array
     * @param value   int 數值
     * @return        byte array
     */
    //byte[] bytes = ByteBuffer.allocate(4).putInt(1695609641).array();
    //final will prevent the method from being hidden by subclasses
    public static final byte[] intToByteArray(int value) 
    {
        byte[] bytes = ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(value).array();        
        return bytes;

//BIG_ENDIAN
//        return new byte[] {
//                (byte)(value >>> 24),
//                (byte)(value >>> 16),
//                (byte)(value >>> 8),
//                (byte)value};

//LITTLE_ENDIAN        
//        return new byte[]
//            { (byte) value, (byte) (value >>> 8), (byte) (value >>> 16), (byte) (value >>> 24) };
        
    }
    
    /**
     * Convert byte array to int
     * @param buf byte array to convert
     * @param isBigEndian  true = big endian, false = little endian
     * @return result int value
     */
    public static int byteArrayToInt(byte [] buf, boolean isBigEndian)
    {
        if (isBigEndian)
        {
            return java.nio.ByteBuffer.wrap(buf).getInt();          
        }
        else
        {
            return java.nio.ByteBuffer.wrap(buf).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
        }
    }
    
    /**
     * Set bit value of given byte
     * @param b           要設定的 byte
     * @param pos         要設定的位元 由 7~0 
     * @param op          0=清除, 1=設定, 2=反向
     * @return result byte
     */
    public static byte setBit(byte b, int pos, int op)
    {
        if (op == 0)
        {
            return (byte) (b & ~(1 << pos));
        }
        else if (op == 1)
        {
            return (byte) (b | (1 << pos));         
        }
        else
        {
            return (byte) (b ^ (1 << pos));
        }
    }

    /**
     * Convert byte array to bit string 
     * @param bitMap byte array to convert
     * @return result bit string
     */
    public static String showBitMap(byte[] bitMap)
    {
        String ret = "";
        for(int i=0; i < bitMap.length; i++)
        {
            ret = ret + String.format("%8s", Integer.toBinaryString(bitMap[i] & 0xFF)).replace(' ', '0');
        }
        return ret;
    }
    
    
    /**
     * Convert byte array data to hex string.
     * @param b byte array to convert
     * @return result string
     */
    public static String byteArrayToHexString(byte[] b)
    {
        char hexDigit[] =
            { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        StringBuffer buf = new StringBuffer();
        for (int j = 0; j < b.length; j++)
        {
            buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
            buf.append(hexDigit[b[j] & 0x0f]);
        }
        return buf.toString();
    }

    /**
     * convert hex string to byte array
     * @param s hex string to convert
     * @return result byte array
     */
    public static byte[] hexStringToByteArray(String s)
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * 將16進位資料壓縮為二進位值
     * 
     * @param hexStr 16進位字串，長度必需為 2 的倍數
     * @return byte [] 壓縮後的二進位值資料陣列
     */
    public static byte[] pack(String hexStr)
    {
        int size = hexStr.length();

        if ((size % 2) != 0)
        {
            return null;
        }

        int[] intData = new int[size / 2];
        int j = 0;
        for (int i = 0; i < size; i += 2)
        {
            intData[j] = Integer.parseInt(hexStr.substring(i, i + 2), 16);
            j++;
        }

        byte[] outputByte = new byte[intData.length];
        for (int x = 0; x < intData.length; x++)
        {
            outputByte[x] = (byte) intData[x];
        }
        return outputByte;
    }  //pack

    /**
     * 將二進位資料展開為 16 進位值
     * 
     * @param bin 二進位資料陣列
     * @return byte [] 展開後的16 進位值資料陣列
     */
    public static byte[] unpack(byte[] bin)
    {
        int size = bin.length;
        byte[] hex = new byte[2 * size];

        int i = 0;
        for (int j = 0; i < size;)
        {
            int rawByte = bin[i];
            if (rawByte < 0)
                rawByte += 256;

            int nibble = rawByte >> 4;
            if (nibble < 10)
            {
                hex[j] = (byte) (48 + nibble); // 0 ~ 9
            }
            else
            {
                hex[j] = (byte) (65 + nibble - 10); // A ~ F
            }

            nibble = rawByte & 0x0000000F;
            if (nibble < 10)
            {
                hex[(j + 1)] = (byte) (48 + nibble);
            }
            else
            {
                hex[(j + 1)] = (byte) (65 + nibble - 10);
            }

            i++;
            j += 2; // 展開成雙倍長度
        }

        return hex;
    }  //unpack
    
    //--------------------------------------------------------------
    
    public static final int DUMP_HEX=0, DUMP_ASCII=1, DUMP_EBCDIC=2, DUMP_ALL=3;  
    static byte[] ebc2asc=
    {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 00-0f */
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, /* 10-1f */
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, /* 20-2f */
      0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 30-3f */
      0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,

      0x20, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, /* 40-4f */
      0x48, 0x49, 0x5E, 0x2E, 0x3C, 0x28, 0x2B, 0x4F,

      0x26, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, /* 50-5f */
      0x58, 0x59, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5F,

      0x2D, 0x2F, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* 60-6f */
      0x68, 0x69, 0x7C, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,

      0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, /* 70-7f */
      0x78, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,

      (byte)0x80, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* 80-8f */
      0x68, 0x69, (byte)0x8A, (byte)0x8B, (byte)0x8C, (byte)0x8D, (byte)0x8E, (byte)0x8F,

      (byte)0x90, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, /* 90-9f */
      0x71, 0x72, (byte)0x9A, (byte)0x9B, (byte)0x9C, (byte)0x9D, (byte)0x9E, (byte)0x9F,

      (byte)0xA0, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, /* a0-af */
      0x79, 0x7A, (byte)0xAA, (byte)0xAB, (byte)0xAC, (byte)0xAD, (byte)0xAE, (byte)0xAF,

      (byte)0xB0, (byte)0xB1, (byte)0xB2, (byte)0xB3, (byte)0xB4, (byte)0xB5, (byte)0xB6, (byte)0xB7, /* b0-bf */
      (byte)0xB8, (byte)0xB9, (byte)0xBA, (byte)0xBB, (byte)0xBC, (byte)0xBD, (byte)0xBE, (byte)0xBF,

      0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, /* c0-cf */
      0x48, 0x49, (byte)0xCA, (byte)0xCB, (byte)0xCC, (byte)0xCD, (byte)0xCE, (byte)0xCF,

      0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, /* d0-df */
      0x51, 0x52, (byte)0xDA, (byte)0xDB, (byte)0xDC, (byte)0xDD, (byte)0xDE, (byte)0xDF,

      0x5C, (byte)0xE1, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, /* e0-ef */
      0x59, 0x5A, (byte)0xEA, (byte)0xEB, (byte)0xEC, (byte)0xED, (byte)0xEE, (byte)0xEF,

      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* f0-ff */
      0x38, 0x39, (byte)0xFA, (byte)0xFB, (byte)0xFC, (byte)0xFD, (byte)0xFE, (byte)0xFF, 
    };


    /*  **********************************************************************  */
    /*  ASCII to EBCDIC Translate Table                                         */
    /*  **********************************************************************  */

    static byte[] asc2ebc =
    {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 00-0f */ 
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, /* 10-0f */
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      
      0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, /* 20-2f */
      0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
      
      (byte)0xF0, (byte)0xF1, (byte)0xF2, (byte)0xF3, (byte)0xF4, (byte)0xF5, (byte)0xF6, (byte)0xF7, /* 30-3f */
      (byte)0xF8, (byte)0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
      
      0x7C, (byte)0xC1, (byte)0xC2, (byte)0xC3, (byte)0xC4, (byte)0xC5, (byte)0xC6, (byte)0xC7, /* 40-4f */         
      (byte)0xC8, (byte)0xC9, (byte)0xD1, (byte)0xD2, (byte)0xD3, (byte)0xD4, (byte)0xD5, (byte)0xD6,
      
      (byte)0xD7, (byte)0xD8, (byte)0xD9, (byte)0xE2, (byte)0xE3, (byte)0xE4, (byte)0xE5, (byte)0xE6, /* 50-5f */
      (byte)0xE7, (byte)0xE8, (byte)0xE9, (byte)0xFF, (byte)0xE0, (byte)0xFF, (byte)0x5F, (byte)0x6D,
      
      0x79, (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87, /* 60-6f */
      (byte)0x88, (byte)0x89, (byte)0x91, (byte)0x92, (byte)0x93, (byte)0x94, (byte)0x95, (byte)0x96,
      
      (byte)0x97, (byte)0x98, (byte)0x99, (byte)0xA2, (byte)0xA3, (byte)0xA4, (byte)0xA5, (byte)0xA6, /* 70-7f */
      (byte)0xA7, (byte)0xA8, (byte)0xA9, (byte)0xC0, 0x6A, (byte)0xD0, (byte)0xA1, 0x7F,

      (byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87, /* 80-8f */
      (byte)0x88, (byte)0x89, (byte)0x8A, (byte)0x8B, (byte)0x8C, (byte)0x8D, (byte)0x8E, (byte)0x8F,

      (byte)0x90, (byte)0x91, (byte)0x92, (byte)0x93, (byte)0x94, (byte)0x95, (byte)0x96, (byte)0x97, /* 90-9f */
      (byte)0x98, (byte)0x99, (byte)0x9A, (byte)0x9B, (byte)0x9C, (byte)0x9D, (byte)0x9E, (byte)0x9F,

      (byte)0xA0, (byte)0xA1, (byte)0xA2, (byte)0xA3, (byte)0xA4, (byte)0xA5, (byte)0xA6, (byte)0xA7, /* a0-af */
      (byte)0xA8, (byte)0xA9, (byte)0xAA, (byte)0xAB, (byte)0xAC, (byte)0xAD, (byte)0xAE, (byte)0xAF,

      (byte)0xB0, (byte)0xB1, (byte)0xB2, (byte)0xB3, (byte)0xB4, (byte)0xB5, (byte)0xB6, (byte)0xB7, /* b0-bf */
      (byte)0xB8, (byte)0xB9, (byte)0xBA, (byte)0xBB, (byte)0xBC, (byte)0xBD, (byte)0xBE, (byte)0xBF,

      (byte)0xC0, (byte)0xC1, (byte)0xC2, (byte)0xC3, (byte)0xC4, (byte)0xC5, (byte)0xC6, (byte)0xC7, /* c0-cf */
      (byte)0xC8, (byte)0xC9, (byte)0xCA, (byte)0xCB, (byte)0xCC, (byte)0xCD, (byte)0xCE, (byte)0xCF,

      (byte)0xD0, (byte)0xD1, (byte)0xD2, (byte)0xD3, (byte)0xD4, (byte)0xD5, (byte)0xD6, (byte)0xD7, /* d0-df */
      (byte)0xD8, (byte)0xD9, (byte)0xDA, (byte)0xDB, (byte)0xDC, (byte)0xDD, (byte)0xDE, (byte)0xDF,

      (byte)0xE0, (byte)0xE1, (byte)0xE2, (byte)0xE3, (byte)0xE4, (byte)0xE5, (byte)0xE6, (byte)0xE7, /* e0-ef */
      (byte)0xE8, (byte)0xE9, (byte)0xEA, (byte)0xEB, (byte)0xEC, (byte)0xED, (byte)0xEE, (byte)0xEF,

      (byte)0xF0, (byte)0xF1, (byte)0xF2, (byte)0xF3, (byte)0xF4, (byte)0xF5, (byte)0xF6, (byte)0xF7, /* f0-ff */
      (byte)0xF8, (byte)0xF9, (byte)0xFA, (byte)0xFB, (byte)0xFC, (byte)0xFD, (byte)0xFE, (byte)0xFF,
    };

    //Application specific output stream, default to System.out
    OutputStream dumpOutputStream = System.out;

    /**
     * Set dump output.
     * Default to System.out.
     * 
     * @param stream        OutputStream to output
     */
    public void setOutputStream(OutputStream stream)
    {
        dumpOutputStream = stream;
    }
    
    /**
     * common function for output debug messages.
     * @param msg output message
     */
    void debug(String msg)
    {
        //System.out.print(msg);
        try
        {
            dumpOutputStream.write(msg.getBytes());
        }
        catch (IOException e)
        {
        }
    }
    
    /**
     * Dump byte array content.
     * 
     * @param option    dump options: DUMP_HEX, DUMP_ASCII, DUMP_EBCDIC
     * @param title     dump message title
     * @param buffer    byte array to dump
     * @param len       dump size
     */
    public void hexDump(int option, String title, byte [] buffer, int len)
    {
        if (title != null)
            debug(title + " : Buffer length " + len + "\n");
        debug("                                          ");
        if ((option & DUMP_ASCII) == DUMP_ASCII)
            debug("      ASCII        ");
        if ((option & DUMP_EBCDIC) == DUMP_EBCDIC)
            debug("      EBCDIC      ");
        debug("\n");
        debug("       0 1 2 3  4 5 6 7  8 9 A B  C D E F ");
        if ((option & DUMP_ASCII) == DUMP_ASCII)
            debug(" 0123456789ABCDEF  ");
        if ((option & DUMP_EBCDIC) == DUMP_EBCDIC)
            debug(" 0123456789ABCDEF ");
        debug("\n");
        toHexString(option, buffer, len);
 
    }
    
    /**
     * Dump input byte array to message output.
     * 
     * @param option dump options: DUMP_HEX, DUMP_ASCII, DUMP_EBCDIC
     * @param block byte array to dump
     * @param length data size to dump
     */
    void toHexString(int option, byte[] block, int length) 
    {
        StringBuffer buf = new StringBuffer("");
        byte[] buf1 = new byte[block.length];
        byte[] buf2 = new byte[block.length];
        int len = length;
        int to_prt, j, k, l, m;
        System.arraycopy(block, 0, buf1, 0, block.length);
        System.arraycopy(block, 0, buf2, 0, block.length);
        k = 0;
        l = 0;
        m = 0;
        for (int i = 0; i < len; i += 16)
        {
            String temp = String.format("%04X: ", i);
            debug(temp);
            // System.out.printf("%04X: ", i);
            to_prt = ((i + 16) > len) ? len - i : 16;
            for (j = 0; j < to_prt; j++)
            {
                if (j % 4 == 0 && j != 0)
                    debug(" ");
                byte2hex(buf1[k], buf);
                debug(buf.toString());
                buf.delete(0, 2);
                k++;
            }

            for (; j < 16; j++)
            {
                if (j % 4 == 0 && j != 0)
                    debug(" ");
                debug("  ");
            }
            if ((option & DUMP_ASCII) == DUMP_ASCII)
            {
                /*
                 ** display ASCII
                 */
                debug(" [");
                for (j = 0; j < to_prt; j++)
                {
                    if (buf2[l] >= 0x20 && buf2[l] <= 0x7e)
                    {
                        String tmpbuf2 = String.format("%c", buf2[l]);
                        debug(tmpbuf2);
                        // System.out.printf("%c",buf2[l]);
                    }
                    else
                        debug(".");
                    l++;
                }
                for (; j < 16; j++)
                {
                    debug(" ");
                }
                debug("]");
            }
            if ((option & DUMP_EBCDIC) == DUMP_EBCDIC)
            {
                /*
                 ** display EBCDIC
                 */
                debug(" [");
                for (j = 0; j < to_prt; j++)
                {
                    int aa = buf2[m] < 0 ? (256 + (buf2[m])) : buf2[m];
                    if ((ebc2asc[aa]) >= 0x20 && (ebc2asc[aa]) <= 0x7e)
                    {
                        String tmpebc2asc = String.format("%c", ebc2asc[aa]);
                        debug(tmpebc2asc);
                        // System.out.printf("%c",ebc2asc[aa]);
                    }
                    else
                        debug(".");
                    m++;
                }
                for (; j < 16; j++)
                {
                    debug(" ");
                }
                debug("]");
            }
            debug("\n");
        }
        debug("\n");
    }
    
    /**
     * Convert byte to hex string and appends to input string buffer.
     * @param b byte to convert
     * @param buf string buffer to append
     */
    void byte2hex(byte b, StringBuffer buf) 
    {
         char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
         '9', 'A', 'B', 'C', 'D', 'E', 'F' };
         int high = ((b & 0xf0) >> 4);
         int low = (b & 0x0f);
         buf.append(hexChars[high]);
         buf.append(hexChars[low]);
    }

    
}
