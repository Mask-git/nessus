import socket
import argparse
import time
import re
from xml.etree import ElementTree as ET

def check_xmpp_anonymous_login(target_ip, port=5222, timeout=10, verbose=False):
    """检测XMPP服务器是否允许匿名登录"""
    results = []
    
    try:
        # 建立TCP连接
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            results.append(f"[+] 正在连接 {target_ip}:{port}...")
            sock.connect((target_ip, port))
            
            # 发送初始流请求
            init_stream = (
                '<stream:stream xmlns="jabber:client" '
                'xmlns:stream="http://etherx.jabber.org/streams" '
                f'to="{target_ip}" version="1.0">'
            ).encode('utf-8')
            results.append(f"[+] 发送初始流请求: {init_stream.decode('utf-8')}")
            sock.send(init_stream)
            
            # 接收服务器响应（循环接收直到流特性结束或超时）
            results.append("[+] 正在接收服务器响应...")
            response = b""
            timeout_time = time.time() + timeout
            while time.time() < timeout_time:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                if b'</stream:features>' in response:
                    results.append("[+] 接收到完整的流特性")
                    break
                elif time.time() >= timeout_time:
                    results.append("[-] 接收超时，可能未收到完整响应")
            
            response_str = response.decode('utf-8', errors='ignore')
            if verbose:
                results.append(f"[+] 服务器完整响应:\n{response_str}")
            else:
                results.append(f"[+] 服务器初始响应: {response_str[:300]}...")
            
            # 保存原始响应用于调试
            original_response = response_str
            
            # 处理XML声明问题
            processed_response = response_str.strip()
            if processed_response.startswith('<?xml'):
                xml_decl_end = processed_response.find('?>') + 2
                processed_response = processed_response[xml_decl_end:].strip()
            
            try:
                # 尝试标准XML解析
                results.append("[+] 尝试使用标准XML解析...")
                root = ET.fromstring(processed_response)
                results.append("[+] 标准解析成功")
            except ET.ParseError as e:
                # 标准解析失败，记录错误并尝试手动提取关键信息
                results.append(f"[-] 标准XML解析失败: {str(e)}")
                results.append("[+] 尝试手动解析关键信息...")
                
                # 提取<stream:features>部分
                features_start = processed_response.find('<stream:features')
                features_end = processed_response.find('</stream:features>') + 19  # 包含标签长度
                
                if features_start >= 0 and features_end > features_start:
                    features_xml = processed_response[features_start:features_end]
                    results.append(f"[+] 成功提取流特性XML片段")
                    if verbose:
                        results.append(f"[+] 流特性XML:\n{features_xml}")
                else:
                    # 尝试更宽松的匹配
                    features_pattern = re.compile(r'<stream:features[^>]*>.*?</stream:features>', re.DOTALL)
                    match = features_pattern.search(processed_response)
                    
                    if match:
                        features_xml = match.group(0)
                        results.append(f"[+] 通过正则表达式提取流特性XML片段")
                        if verbose:
                            results.append(f"[+] 流特性XML:\n{features_xml}")
                    else:
                        results.append("[-] 无法提取流特性信息，分析终止")
                        return "\n".join(results)
                
                # 检查ANONYMOUS机制
                if 'ANONYMOUS' in features_xml:
                    results.append("[!] 检测到ANONYMOUS认证机制")
                else:
                    results.append("[+] 未检测到ANONYMOUS认证机制，服务器不允许匿名登录")
                    return "\n".join(results)
                
                # 由于无法正常解析XML，直接尝试匿名认证
                results.append("[!] 尝试匿名认证...")
                auth = '<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>'.encode('utf-8')
                sock.send(auth)
                results.append(f"[+] 发送匿名认证请求: {auth.decode('utf-8')}")
                
                # 接收认证响应
                auth_response = b""
                timeout_time = time.time() + timeout
                while time.time() < timeout_time:
                    data = sock.recv(4096)
                    if not data:
                        break
                    auth_response += data
                    if b'</stream:stream>' in data or b'<success' in data or b'<failure' in data:
                        break
                
                auth_response_str = auth_response.decode('utf-8', errors='ignore')
                results.append(f"[+] 认证响应: {auth_response_str}")
                
                if '<success' in auth_response_str:
                    results.append("[!!!] 高风险：服务器允许匿名登录，存在安全漏洞")
                    
                    # 尝试获取绑定的JID
                    results.append("[+] 尝试获取匿名会话JID...")
                    try:
                        # 重新初始化流
                        sock.send(init_stream)
                        bind_response = sock.recv(4096).decode('utf-8', errors='ignore')
                        
                        # 绑定资源
                        bind = '<iq type="set" id="bind1"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>anonymous</resource></bind></iq>'.encode('utf-8')
                        results.append(f"[+] 发送资源绑定请求: {bind.decode('utf-8')}")
                        sock.send(bind)
                        
                        bind_result = sock.recv(4096).decode('utf-8', errors='ignore')
                        results.append(f"[+] 绑定响应: {bind_result[:300]}...")
                        
                        # 提取JID
                        jid_match = re.search(r'<jid>(.*?)</jid>', bind_result)
                        if jid_match:
                            jid = jid_match.group(1)
                            results.append(f"[+] 已获取匿名JID: {jid}")
                        else:
                            results.append("[-] 未能提取JID")
                    
                    except Exception as e:
                        results.append(f"[-] 获取JID失败: {str(e)}")
                    
                    # 尝试发送测试消息（谨慎操作）
                    test_msg = input("\n[?] 是否尝试发送测试消息？(y/n): ").strip().lower()
                    if test_msg == 'y':
                        recipient = input("[?] 输入接收方JID (例如 user@domain): ").strip()
                        if recipient:
                            message = (
                                f'<message to="{recipient}" type="chat">'
                                '<body>Test from anonymous client</body>'
                                '</message>'
                            ).encode('utf-8')
                            results.append(f"[+] 发送测试消息到: {recipient}")
                            sock.send(message)
                            
                            # 接收消息响应
                            msg_response = sock.recv(4096).decode('utf-8', errors='ignore')
                            results.append(f"[+] 消息响应: {msg_response[:300]}...")
                    
                    return "\n".join(results)
                else:
                    results.append("[+] 匿名认证被拒绝，服务器配置安全")
                    return "\n".join(results)
            
            # 标准解析成功的流程
            stream_ns = "{http://etherx.jabber.org/streams}"
            sasl_ns = "{urn:ietf:params:xml:ns:xmpp-sasl}"
            
            features = root.find(f"{stream_ns}features")
            if features is None:
                results.append("[-] 未找到流特性，无法继续分析")
                return "\n".join(results)
            
            mechanisms = features.find(f"{sasl_ns}mechanisms")
            if mechanisms is None:
                results.append("[-] 服务器未提供认证机制，无法测试匿名登录")
                return "\n".join(results)
            
            # 获取支持的认证机制
            auth_mechanisms = [mech.text for mech in mechanisms.findall(f"{sasl_ns}mechanism")]
            results.append(f"[+] 服务器支持的认证机制: {', '.join(auth_mechanisms)}")
            
            if 'ANONYMOUS' not in auth_mechanisms:
                results.append("[+] 服务器未启用ANONYMOUS认证机制，无法匿名登录")
                return "\n".join(results)
            
            # 尝试匿名认证
            results.append("[!] 检测到ANONYMOUS机制，正在尝试匿名登录...")
            auth = '<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>'.encode('utf-8')
            sock.send(auth)
            results.append(f"[+] 发送匿名认证请求: {auth.decode('utf-8')}")
            
            # 接收认证响应
            auth_response = b""
            timeout_time = time.time() + timeout
            while time.time() < timeout_time:
                data = sock.recv(4096)
                if not data:
                    break
                auth_response += data
                if b'</stream:stream>' in data or b'<success' in data or b'<failure' in data:
                    break
            
            auth_response_str = auth_response.decode('utf-8', errors='ignore')
            results.append(f"[+] 认证响应: {auth_response_str}")
            
            if '<success' in auth_response_str:
                results.append("[!!!] 高风险：服务器允许匿名登录，存在安全漏洞")
                
                # 尝试获取绑定的JID
                results.append("[+] 尝试获取匿名会话JID...")
                try:
                    # 重新初始化流
                    sock.send(init_stream)
                    bind_response = sock.recv(4096).decode('utf-8', errors='ignore')
                    
                    # 绑定资源
                    bind = '<iq type="set" id="bind1"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>anonymous</resource></bind></iq>'.encode('utf-8')
                    results.append(f"[+] 发送资源绑定请求: {bind.decode('utf-8')}")
                    sock.send(bind)
                    
                    bind_result = sock.recv(4096).decode('utf-8', errors='ignore')
                    results.append(f"[+] 绑定响应: {bind_result[:300]}...")
                    
                    # 提取JID
                    jid_match = re.search(r'<jid>(.*?)</jid>', bind_result)
                    if jid_match:
                        jid = jid_match.group(1)
                        results.append(f"[+] 已获取匿名JID: {jid}")
                    else:
                        results.append("[-] 未能提取JID")
                
                except Exception as e:
                    results.append(f"[-] 获取JID失败: {str(e)}")
                
                # 尝试发送测试消息（谨慎操作）
                test_msg = input("\n[?] 是否尝试发送测试消息？(y/n): ").strip().lower()
                if test_msg == 'y':
                    recipient = input("[?] 输入接收方JID (例如 user@domain): ").strip()
                    if recipient:
                        message = (
                            f'<message to="{recipient}" type="chat">'
                            '<body>Test from anonymous client</body>'
                            '</message>'
                        ).encode('utf-8')
                        results.append(f"[+] 发送测试消息到: {recipient}")
                        sock.send(message)
                        
                        # 接收消息响应
                        msg_response = sock.recv(4096).decode('utf-8', errors='ignore')
                        results.append(f"[+] 消息响应: {msg_response[:300]}...")
            
            else:
                results.append("[+] 匿名认证被拒绝，服务器配置安全")
            
            return "\n".join(results)
    
    except socket.timeout:
        return "[-] 连接超时，服务器可能未响应或端口被防火墙屏蔽"
    except ConnectionRefusedError:
        return "[-] 连接被拒绝，端口可能未开放或服务未运行"
    except Exception as e:
        return f"[-] 发生未知错误: {str(e)}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XMPP匿名登录检测工具")
    parser.add_argument("target_ip", help="目标IP地址")
    parser.add_argument("-p", "--port", type=int, default=5222, help="端口号（默认5222）")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="超时时间（秒）")
    args = parser.parse_args()

    print("="*50)
    print(f"XMPP匿名登录检测 - 目标: {args.target_ip}:{args.port}")
    print("="*50)
    
    result = check_xmpp_anonymous_login(args.target_ip, args.port, args.timeout, args.verbose)
    print(result)
    
