import weblogic.servlet.logging.CustomELFLogger;
import weblogic.servlet.logging.FormatStringBuffer;
import weblogic.servlet.logging.HttpAccountingInfo;
import java.lang.reflect.Method;

public class OPRIDLogField implements CustomELFLogger
{
	public void logField(HttpAccountingInfo metrics, FormatStringBuffer buff)
	{
	        Object psperfenv = metrics.getAttribute("psperfenv");
	        if(psperfenv != null)
	        {
	                try
	                {
	                        Method getOperID = psperfenv.getClass().getMethod("getOPERID");
	                        buff.appendValueOrDash(getOperID.invoke(psperfenv).toString());
	                }
	                catch(Exception e)
	                {
	                        buff.appendValueOrDash("exception");
	                }
	        }
	
	}
}
