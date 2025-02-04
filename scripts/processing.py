import pandas as pd
import pyshark

cap = pyshark.FileCapture('shark1.pcapng')
cap

conversations = pd.DataFrame(columns=["IPV4_SRC_ADDR","L4_SRC_PORT","IPV4_DST_ADDR","L4_DST_PORT",
                                        "PROTOCOL","L7_PROTO","IN_BYTES","OUT_BYTES","IN_PKTS",
                                        "OUT_PKTS","TCP_FLAGS","FLOW_DURATION_MILLISECONDS"])
def getdemflags(packet):
    if hasattr(packet, 'tcp'):
        flag_attributes = ['flags_ack', 'flags_ae', 'flags_cwr', 'flags_ece',
                            'flags_fin', 'flags_push', 'flags_res', 'flags_reset',
                            'flags_str', 'flags_urg']
        flags_sum = sum(1 if getattr(packet.tcp, flag, 'False') == 'True' else 0 for flag in flag_attributes)
        return flags_sum
    else:
        return 0


for packets in cap:
    if 'IP' in packets:
            new_row = {"IPV4_SRC_ADDR":packets.IP.src,"L4_SRC_PORT":packets[packets.transport_layer].srcport,
                            "IPV4_DST_ADDR":packets.IP.dst,"L4_DST_PORT":packets[packets.transport_layer].dstport, 
                            "PROTOCOL":packets.IP.proto,"L7_PROTO":0,"IN_BYTES":len(packets),
                            "OUT_BYTES":0,"IN_PKTS":1,"OUT_PKTS":0,"TCP_FLAGS":getdemflags(packets),
                            "FLOW_DURATION_MILLISECONDS":float(packets[packets.transport_layer].time_relative)}
            conversations = pd.concat([conversations, pd.DataFrame([new_row])], ignore_index=True)

imp_cols = ["IPV4_SRC_ADDR","L4_SRC_PORT","IPV4_DST_ADDR","L4_DST_PORT"]
imp_cols_out = ["IPV4_DST_ADDR","L4_DST_PORT","IPV4_SRC_ADDR","L4_SRC_PORT"]


conversations['CONVERSATION_KEY'] = conversations.apply(
    lambda row: tuple(sorted([(row['IPV4_SRC_ADDR'], row['L4_SRC_PORT']),
                            (row['IPV4_DST_ADDR'], row['L4_DST_PORT'])])),axis=1)

grouped = conversations.groupby('CONVERSATION_KEY')

consolidated_conversations = grouped.apply(lambda group: pd.Series({
    'IPV4_SRC_ADDR': group.iloc[0]['IPV4_SRC_ADDR'],
    'L4_SRC_PORT': group.iloc[0]['L4_SRC_PORT'],
    'IPV4_DST_ADDR': group.iloc[0]['IPV4_DST_ADDR'],
    'L4_DST_PORT': group.iloc[0]['L4_DST_PORT'],
    'PROTOCOL': group.iloc[0]['PROTOCOL'],
    'L7_PROTO': group.iloc[0]['L7_PROTO'],
    'IN_BYTES': group.loc[group['IPV4_SRC_ADDR'] == group.iloc[0]['IPV4_SRC_ADDR'], 'IN_BYTES'].sum(),
    'OUT_BYTES': group.loc[group['IPV4_DST_ADDR'] == group.iloc[0]['IPV4_SRC_ADDR'], 'IN_BYTES'].sum(),
    'IN_PKTS': group.loc[group['IPV4_SRC_ADDR'] == group.iloc[0]['IPV4_SRC_ADDR'], 'IN_PKTS'].sum(),
    'OUT_PKTS': group.loc[group['IPV4_DST_ADDR'] == group.iloc[0]['IPV4_SRC_ADDR'], 'IN_PKTS'].sum(),
    'TCP_FLAGS': group['TCP_FLAGS'].sum(),
    'FLOW_DURATION_MILLISECONDS': group['FLOW_DURATION_MILLISECONDS'].sum(),
})).reset_index(drop=True)

print(consolidated_conversations)