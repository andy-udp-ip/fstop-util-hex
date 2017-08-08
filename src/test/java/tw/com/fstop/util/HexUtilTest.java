
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
        byte [] b = null;
        String h = null;
        
        b = HexUtil.hexStringToByteArray(s);
        assertNotNull(b);
        
        h = HexUtil.byteArrayToHexString(b);
        assertThat(h).isEqualToIgnoringCase(s);
        
        b = HexUtil.pack(s);
        assertNotNull(b);
        
        b = HexUtil.unpack(b);
        h = new String (b);
        assertThat(h).isEqualToIgnoringCase(s);
        
        
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
