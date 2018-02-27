package org.graylog2.alarmcallbacks.jabber.smack;

import org.jivesoftware.smack.chat2.Chat;
import org.jivesoftware.smack.chat2.IncomingChatMessageListener;
import org.jivesoftware.smack.packet.Message;
import org.jxmpp.jid.EntityBareJid;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class IncomingListener implements IncomingChatMessageListener {
    public final Map<String, Message> messages = new ConcurrentHashMap<>();

    @Override
    public void newIncomingMessage(EntityBareJid from, Message message, Chat chat) {
        messages.put(from.asEntityBareJidString(), message);
    }
}
