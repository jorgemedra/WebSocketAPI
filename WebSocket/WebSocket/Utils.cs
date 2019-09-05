using System;
using System.Text;

namespace jomt.websocket.utils
{
    public enum WsRxStatus
    {
        Offline,
        Handshaking,
        OpcodeMaskPayLoad,
        MaskPayLoadExt,
        MaskPayLoadExtBig,
        MaskingKey,
        Payload
    }

    public enum OpCodes
    {
        CONTINUE = 0, /* 0x00 = 00000000 */
        TEXT = 1,         /* 0x01 = 00000001 */
        BINARY = 2,       /* 0x02 = 00000010 */
        CLOSE = 8,   /* 0x08 = 00001000 */
        PING = 9,              /* 0x09 = 00001001 */
        PONG = 10              /* 0x0A = 00010000 */
    }

    public class Frame
    {
        public bool IsRX { get; set; }
        public bool FIN { get; set; }
        public bool RSV1 { get; set; }
        public bool RSV2 { get; set; }
        public bool RSV3 { get; set; }
        public byte OpCode { get; set; }
        public bool IsMASKING { get; set; }
        public int PayLoadLen { get; set; }
        public byte[] MaskingKey = null;
        public byte[] PayLoad = null;
        public string TextData = null;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(string.Format("{0} FRAME INFO", IsRX ? "RX>>" : "TX<<"));

            OpCodes oc = (OpCodes)OpCode;
            string info = string.Format("\tFIN:{0}\tRSV1: {1}\tRSV2: {2}\tRSV3: {3}\tOpCode: {4}",
                    FIN ? 1 : 0,
                    RSV1 ? 1 : 0,
                    RSV2 ? 1 : 0,
                    RSV3 ? 1 : 0,
                    oc);
            sb.AppendLine(info);

            info = string.Format("\tIS MASKING: {0}\tMASK(HEX): [", IsMASKING ? 1 : 0);
            sb.Append(info);
            if (IsMASKING)
            {
                string hex = BitConverter.ToString(MaskingKey, 0, MaskingKey.Length);
                sb.Append(hex);
            }
            sb.AppendLine("]");

            sb.AppendFormat("\tPlayLoad len: {0}", PayLoadLen);
            sb.AppendLine();

            if (PayLoad != null && PayLoad.Length > 0)
            {
                string hex = BitConverter.ToString(PayLoad, 0, PayLoad.Length);
                sb.AppendFormat("\tPayLoad (HEX): [{0}]", hex);

                if (OpCode == (byte)OpCodes.TEXT)
                {
                    string message = Encoding.UTF8.GetString(PayLoad);
                    sb.AppendLine();
                    sb.Append("\tPayLoad (TEXT): [" + message + "]");
                }

            }
            else
                sb.Append("\tPayLoad: NULL");

            return sb.ToString();
        }
    }
}
