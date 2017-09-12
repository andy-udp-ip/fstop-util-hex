
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.math.BigInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.*;

public class HexUtilTest
{
    @Before    
    public void setup() 
    {
    }
    
    @After
    public void tearDown() 
    {
    }

    @Test
    public void testHexUtil() throws FileNotFoundException
    {
        String s = "0123456789ABCDEFBB40";
        byte [] c = null;
        byte [] b = null;
        byte [] a = null;
        String h = null;
        float f;
        int i;
        int j;
        
        b = new byte [2];
        b[0] = (byte) 0xb7;
        b[1] = 0x00;
        
        h = HexUtil.showBitMap(b);
        assertThat(h).isEqualToIgnoringCase("1011011100000000");
        
        b[0] = HexUtil.setBit(b[0], 7, 0);
        h = HexUtil.showBitMap(b);
        assertThat(h).isEqualToIgnoringCase("0011011100000000");
                
        b = new byte[] {(byte) 0xAE, (byte) 0x41, (byte) 0x56, (byte) 0x52};
        a = HexUtil.byteOrder(b, 0);
        assertThat(b).isEqualTo(a);
        
        c = new byte[] {(byte) 0x56, (byte) 0x52, (byte) 0xAE, (byte) 0x41};
        a = HexUtil.byteOrder(b, 1);
        assertThat(a).isEqualTo(c);
        
        c = new byte[] {(byte) 0x41, (byte) 0xAE, (byte) 0x52, (byte) 0x56};
        a = HexUtil.byteOrder(b, 2);
        assertThat(a).isEqualTo(c);

        c = new byte[] {(byte) 0x52, (byte) 0x56, (byte) 0x41, (byte) 0xAE};
        a = HexUtil.byteOrder(b, 3);
        assertThat(a).isEqualTo(c);
        
        f = 100;
        //IEEE 754 floating-point single-format bit layout
        c = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0xc8, (byte) 0x42};
        b = HexUtil.floatToByteArray(f);
        assertThat(b).isEqualTo(c);
        
        i = 100;
        c = new byte[] {(byte) 0x64, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        b = HexUtil.intToByteArray(i);
        assertThat(b).isEqualTo(c);
        
        j = HexUtil.byteArrayToInt(b, false);
        assertThat(j).isEqualTo(i);
        
        
        b = HexUtil.hexStringToByteArray(s);
        assertNotNull(b);
        
        h = HexUtil.byteArrayToHexString(b);
        assertThat(h).isEqualToIgnoringCase(s);
        
        b = HexUtil.pack(s);
        assertNotNull(b);
        
        b = HexUtil.unpack(b);
        h = new String (b);
        assertThat(h).isEqualToIgnoringCase(s);
        
        
        //--
        s = "0123456789abcdef";
        b = HexUtil.pack(s);
        long l = HexUtil.byteArrayToLong(b, false);
        System.out.println("Long=" + l);
        l = l + 1;
        System.out.println("Long=" + l);
        b = HexUtil.longToByteArray(l);
        s = HexUtil.byteArrayToHexString(b);
        System.out.println("LONG=" + s);
         
        //-------------------------------------------
        HexUtil util = new HexUtil();
        
        util.hexDump(HexUtil.DUMP_ASCII, "Dump ASCII", b, b.length);
        util.hexDump(HexUtil.DUMP_EBCDIC, "Dump EBCDIC", b, b.length);
        util.hexDump(HexUtil.DUMP_HEX, "Dump HEX", b, b.length);
        util.hexDump(HexUtil.DUMP_ASCII | HexUtil.DUMP_EBCDIC | HexUtil.DUMP_HEX, "Dump ALL", b, b.length);
        util.hexDump(HexUtil.DUMP_ALL, "Dump ALL", b, b.length);
        
        FileOutputStream fos = new FileOutputStream("C:/Users/andy/AppData/Local/Temp/log.txt", true);
        util.setOutputStream(fos);
        util.hexDump(HexUtil.DUMP_ALL, "Dump ALL", b, b.length);
        
        
    }
    
}
