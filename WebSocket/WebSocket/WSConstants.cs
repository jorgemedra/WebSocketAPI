using System;
namespace jomt.websocket
{
    enum WSError
    {
        OK = 0,
        ALREADY_STARTED,
        ON_START_WAITING,
        ON_WAIT_CNX,
        NOT_RUNNING,
        SSL_ERROR,
        STARTING_ERROR,
        CLOSING_ERROR,
        HANDSHACKING_ERROR,
        TX_ERROR,
        TX_FRAME_ERROR,
        TX_TEXT_ERROR,
        TX_BINARY_ERROR,
        RX_FRAME_ERROR,
        BAD_OPCODE_ERROR
    }
}
