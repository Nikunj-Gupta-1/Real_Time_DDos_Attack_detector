import pandas as pd
import numpy as np
from scapy.all import sniff, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from collections import defaultdict, Counter
import time
import threading
import joblib
from datetime import datetime
import json
import os
import ipaddress
import logging
import warnings

# Suppress sklearn feature name warnings
warnings.filterwarnings('ignore', message='X does not have valid feature names')
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OptimizedDDoSDetector:
    """
    Enhanced real-time DDoS detection system with false positive reduction
    """
    
    def __init__(self, model_path='optimized_ddos_model.pkl', confidence_threshold=0.85):
        self.flows = defaultdict(dict)
        self.flow_timeout = 300  # Increased timeout for better flow aggregation
        self.model_data = None
        self.alerts = []
        self.confidence_threshold = confidence_threshold  # Configurable threshold
        self.stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'alerts_generated': 0,
            'benign_flows': 0,
            'attack_flows': 0,
            'filtered_broadcasts': 0,
            'low_confidence_filtered': 0
        }
        
        # Network context for filtering
        self.broadcast_addresses = {
            '255.255.255.255',  # IPv4 broadcast
            '224.0.0.1',        # All hosts multicast
            '239.255.255.250',  # UPnP multicast
        }
        
        self.legitimate_services = {
            67: 'DHCP Server',
            68: 'DHCP Client', 
            137: 'NetBIOS Name Service',
            138: 'NetBIOS Datagram Service',
            1900: 'UPnP SSDP',
            5353: 'mDNS'
        }
        
        # Load trained model
        self.load_model(model_path)
        
    def load_model(self, model_path):
        """Load the trained DDoS detection model with enhanced error handling"""
        try:
            if os.path.exists(model_path):
                self.model_data = joblib.load(model_path)
                logger.info("✓ DDoS detection model loaded successfully")
                logger.info(f"Model classes: {list(self.model_data['label_encoder'].classes_)}")
                logger.info(f"Confidence threshold: {self.confidence_threshold:.2f}")
                return True
            else:
                logger.error(f"✗ Model file {model_path} not found!")
                logger.error("Please train the model first using train_ddos_model.py")
                return False
        except Exception as e:
            logger.error(f"✗ Error loading model: {e}")
            return False
    
    def is_broadcast_or_multicast(self, ip_address):
        """Check if IP address is broadcast or multicast"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_multicast or ip.is_broadcast or ip_address in self.broadcast_addresses
        except:
            return False
    
    def is_legitimate_service_traffic(self, flow_data):
        """Identify legitimate network service traffic"""
        src_ip = flow_data.get('src_ip', '')
        dst_ip = flow_data.get('dst_ip', '')
        protocol = flow_data.get('protocol', 0)
        
        # Check for broadcast/multicast destinations
        if self.is_broadcast_or_multicast(dst_ip):
            return True, f"Broadcast/Multicast traffic to {dst_ip}"
        
        # Check for private network ranges
        try:
            src_net = ipaddress.ip_address(src_ip)
            dst_net = ipaddress.ip_address(dst_ip)
            if src_net.is_private and dst_net.is_private:
                # Internal network traffic patterns
                packet_count = flow_data.get('fwd_packets', 0) + flow_data.get('bwd_packets', 0)
                duration = flow_data.get('duration', 0)
                
                # Low-volume, short-duration internal traffic is likely legitimate
                if packet_count < 50 and duration < 30:
                    return True, "Low-volume internal network traffic"
        except:
            pass
        
        return False, ""
    
    def get_flow_key(self, pkt):
        """Generate unique flow identifier from packet with enhanced error handling"""
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                
                src_port = dst_port = 0
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                
                # Create bidirectional flow key
                flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]) + [protocol])
                return flow_key
        except Exception as e:
            logger.debug(f"Error creating flow key: {e}")
        return None
    
    def extract_flow_features(self, flow_data):
        """Extract features with improved error handling and validation"""
        features = {}
        
        try:
            # Basic flow statistics with validation
            duration = max(flow_data.get('duration', 0.001), 0.001)  # Ensure positive duration
            features[' Flow Duration'] = duration * 1000000  # Convert to microseconds
            features[' Total Fwd Packets'] = max(flow_data.get('fwd_packets', 0), 0)
            features[' Total Backward Packets'] = max(flow_data.get('bwd_packets', 0), 0)
            features['Total Length of Fwd Packets'] = max(flow_data.get('fwd_bytes', 0), 0)
            features[' Total Length of Bwd Packets'] = max(flow_data.get('bwd_bytes', 0), 0)
            
            # Packet size statistics with safety checks
            fwd_lengths = flow_data.get('fwd_packet_lengths', [])
            bwd_lengths = flow_data.get('bwd_packet_lengths', [])
            
            features[' Fwd Packet Length Max'] = max(fwd_lengths) if fwd_lengths else 0
            features[' Fwd Packet Length Min'] = min(fwd_lengths) if fwd_lengths else 0
            features[' Fwd Packet Length Mean'] = np.mean(fwd_lengths) if fwd_lengths else 0
            features[' Fwd Packet Length Std'] = np.std(fwd_lengths) if fwd_lengths else 0
            features['Bwd Packet Length Max'] = max(bwd_lengths) if bwd_lengths else 0
            features[' Bwd Packet Length Min'] = min(bwd_lengths) if bwd_lengths else 0
            features[' Bwd Packet Length Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
            features[' Bwd Packet Length Std'] = np.std(bwd_lengths) if bwd_lengths else 0
            
            # Flow rates with improved calculations
            total_bytes = features['Total Length of Fwd Packets'] + features[' Total Length of Bwd Packets']
            total_packets = features[' Total Fwd Packets'] + features[' Total Backward Packets']
            
            features['Flow Bytes/s'] = total_bytes / duration
            features[' Flow Packets/s'] = total_packets / duration
            
            # Inter-arrival times with validation
            fwd_iats = [iat for iat in flow_data.get('fwd_iats', []) if iat >= 0]
            bwd_iats = [iat for iat in flow_data.get('bwd_iats', []) if iat >= 0]
            all_iats = fwd_iats + bwd_iats
            
            features[' Flow IAT Mean'] = np.mean(all_iats) if all_iats else 0
            features[' Flow IAT Std'] = np.std(all_iats) if all_iats else 0
            features[' Flow IAT Max'] = max(all_iats) if all_iats else 0
            features[' Flow IAT Min'] = min(all_iats) if all_iats else 0
            
            features[' Fwd IAT Mean'] = np.mean(fwd_iats) if fwd_iats else 0
            features[' Fwd IAT Std'] = np.std(fwd_iats) if fwd_iats else 0
            features[' Fwd IAT Max'] = max(fwd_iats) if fwd_iats else 0
            features[' Fwd IAT Min'] = min(fwd_iats) if fwd_iats else 0
            
            features[' Bwd IAT Mean'] = np.mean(bwd_iats) if bwd_iats else 0
            features[' Bwd IAT Std'] = np.std(bwd_iats) if bwd_iats else 0
            features[' Bwd IAT Max'] = max(bwd_iats) if bwd_iats else 0
            features[' Bwd IAT Min'] = min(bwd_iats) if bwd_iats else 0
            
            features['Fwd IAT Total'] = sum(fwd_iats) if fwd_iats else 0
            features['Bwd IAT Total'] = sum(bwd_iats) if bwd_iats else 0
            
            # TCP flags
            features['Fwd PSH Flags'] = flow_data.get('fwd_psh_flags', 0)
            features[' Bwd PSH Flags'] = flow_data.get('bwd_psh_flags', 0)
            features[' ACK Flag Count'] = flow_data.get('ack_flags', 0)
            features[' SYN Flag Count'] = flow_data.get('syn_flags', 0)
            features['FIN Flag Count'] = flow_data.get('fin_flags', 0)
            features[' RST Flag Count'] = flow_data.get('rst_flags', 0)
            features[' URG Flag Count'] = flow_data.get('urg_flags', 0)
            features[' PSH Flag Count'] = flow_data.get('psh_flags', 0)
            
            # Additional packet statistics
            all_lengths = fwd_lengths + bwd_lengths
            features[' Packet Length Mean'] = np.mean(all_lengths) if all_lengths else 0
            features[' Packet Length Std'] = np.std(all_lengths) if all_lengths else 0
            features[' Packet Length Variance'] = np.var(all_lengths) if all_lengths else 0
            features[' Max Packet Length'] = max(all_lengths) if all_lengths else 0
            features[' Min Packet Length'] = min(all_lengths) if all_lengths else 0
            features[' Average Packet Size'] = features[' Packet Length Mean']
            
            # Ratio calculations with safety checks
            fwd_bytes = max(features['Total Length of Fwd Packets'], 1)
            fwd_packets = max(features[' Total Fwd Packets'], 1)
            bwd_packets = max(features[' Total Backward Packets'], 1)
            
            features[' Down/Up Ratio'] = features[' Total Length of Bwd Packets'] / fwd_bytes
            features[' Avg Fwd Segment Size'] = features['Total Length of Fwd Packets'] / fwd_packets
            features[' Avg Bwd Segment Size'] = features[' Total Length of Bwd Packets'] / bwd_packets
            features['Fwd Packets/s'] = features[' Total Fwd Packets'] / duration
            features[' Bwd Packets/s'] = features[' Total Backward Packets'] / duration
            features[' Protocol'] = flow_data.get('protocol', 6)
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return default features on error
            for key in [' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets']:
                features.setdefault(key, 0)
        
        return features
    
    def analyze_packet(self, pkt):
        """Enhanced packet analysis with improved flow tracking"""
        self.stats['packets_processed'] += 1
        
        flow_key = self.get_flow_key(pkt)
        if not flow_key:
            return
        
        current_time = time.time()
        
        # Initialize flow if new
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'fwd_iats': [],
                'bwd_iats': [],
                'last_fwd_time': 0,
                'last_bwd_time': 0,
                'syn_flags': 0,
                'ack_flags': 0,
                'fin_flags': 0,
                'rst_flags': 0,
                'psh_flags': 0,
                'urg_flags': 0,
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'protocol': pkt[IP].proto if IP in pkt else 6,
                'src_ip': pkt[IP].src if IP in pkt else '',
                'dst_ip': pkt[IP].dst if IP in pkt else '',
                'first_seen': current_time
            }
        
        flow = self.flows[flow_key]
        packet_length = len(pkt)
        
        # Improved direction detection
        if not flow.get('direction_established', False):
            flow['primary_src'] = pkt[IP].src if IP in pkt else ''
            flow['direction_established'] = True
        
        is_forward = (pkt[IP].src == flow['primary_src']) if IP in pkt else True
        
        # Update flow statistics
        if is_forward:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_length
            flow['fwd_packet_lengths'].append(packet_length)
            if flow['last_fwd_time'] > 0:
                iat = max(0, (current_time - flow['last_fwd_time']) * 1000000)
                flow['fwd_iats'].append(iat)
            flow['last_fwd_time'] = current_time
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_length
            flow['bwd_packet_lengths'].append(packet_length)
            if flow['last_bwd_time'] > 0:
                iat = max(0, (current_time - flow['last_bwd_time']) * 1000000)
                flow['bwd_iats'].append(iat)
            flow['last_bwd_time'] = current_time
        
        # Update TCP flags
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02: flow['syn_flags'] += 1
            if flags & 0x10: flow['ack_flags'] += 1
            if flags & 0x01: flow['fin_flags'] += 1
            if flags & 0x04: flow['rst_flags'] += 1
            if flags & 0x08:
                flow['psh_flags'] += 1
                if is_forward:
                    flow['fwd_psh_flags'] += 1
                else:
                    flow['bwd_psh_flags'] += 1
            if flags & 0x20: flow['urg_flags'] += 1
        
        # Update flow duration
        flow['duration'] = current_time - flow['start_time']
        flow['last_time'] = current_time
        
        # Check for DDoS with improved thresholds
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        if self.model_data and total_packets >= 3:  # Lowered threshold for faster detection
            self.predict_ddos(flow_key, flow)
        
        # Clean up old flows periodically
        if self.stats['packets_processed'] % 1000 == 0:
            self.cleanup_old_flows(current_time)
    
    def cleanup_old_flows(self, current_time):
        """Remove expired flows to manage memory"""
        expired_flows = []
        for flow_key, flow_data in self.flows.items():
            if current_time - flow_data['last_time'] > self.flow_timeout:
                expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            del self.flows[flow_key]
        
        if expired_flows:
            logger.debug(f"Cleaned up {len(expired_flows)} expired flows")
    
    def predict_ddos(self, flow_key, flow_data):
        """Enhanced DDoS prediction with comprehensive filtering - Fixed sklearn warnings"""
        try:
            # Pre-filtering: Check for legitimate service traffic
            is_legitimate, reason = self.is_legitimate_service_traffic(flow_data)
            if is_legitimate:
                self.stats['filtered_broadcasts'] += 1
                self.stats['benign_flows'] += 1
                logger.debug(f"Filtered legitimate traffic: {reason}")
                return
            
            # Extract features
            features = self.extract_flow_features(flow_data)
            
            # Create feature vector matching training data with proper feature names
            if 'feature_names' not in self.model_data:
                logger.error("Feature names not found in model data")
                return
                
            feature_names = self.model_data['feature_names']
            
            # Create pandas DataFrame with proper column names instead of numpy array
            feature_data = {}
            for feature_name in feature_names:
                feature_data[feature_name] = [features.get(feature_name, 0)]
            
            # Convert to DataFrame with proper feature names
            feature_df = pd.DataFrame(feature_data)
            
            # Handle any infinite or NaN values
            feature_df = feature_df.replace([np.inf, -np.inf], np.nan)
            feature_df = feature_df.fillna(0)
            
            # Scale features using DataFrame (preserves feature names)
            if 'scaler' not in self.model_data:
                logger.error("Scaler not found in model data")
                return
                
            feature_df_scaled = pd.DataFrame(
                self.model_data['scaler'].transform(feature_df),
                columns=feature_names
            )
            
            # Predict using DataFrame with feature names
            prediction = self.model_data['model'].predict(feature_df_scaled)[0]
            probability = self.model_data['model'].predict_proba(feature_df_scaled)[0]
            
            # Decode prediction
            predicted_label = self.model_data['label_encoder'].inverse_transform([prediction])[0]
            confidence = max(probability)
            
            # Apply confidence threshold filtering
            if predicted_label != 'BENIGN' and confidence < self.confidence_threshold:
                self.stats['low_confidence_filtered'] += 1
                self.stats['benign_flows'] += 1
                logger.debug(f"Filtered low confidence prediction: {predicted_label} ({confidence:.2f})")
                return
            
            # Update statistics
            if predicted_label == 'BENIGN':
                self.stats['benign_flows'] += 1
            else:
                self.stats['attack_flows'] += 1
                
                # Generate enhanced alert
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'flow_key': str(flow_key),
                    'attack_type': predicted_label,
                    'confidence': float(confidence),
                    'source_ip': flow_data.get('src_ip', ''),
                    'destination_ip': flow_data.get('dst_ip', ''),
                    'protocol': flow_data.get('protocol', 0),
                    'flow_stats': {
                        'duration': flow_data['duration'],
                        'total_packets': flow_data['fwd_packets'] + flow_data['bwd_packets'],
                        'total_bytes': flow_data['fwd_bytes'] + flow_data['bwd_bytes'],
                        'packets_per_second': (flow_data['fwd_packets'] + flow_data['bwd_packets']) / max(flow_data['duration'], 0.001),
                        'bytes_per_second': (flow_data['fwd_bytes'] + flow_data['bwd_bytes']) / max(flow_data['duration'], 0.001)
                    },
                    'risk_level': 'HIGH' if confidence > 0.95 else 'MEDIUM' if confidence > 0.85 else 'LOW'
                }
                
                self.alerts.append(alert)
                self.stats['alerts_generated'] += 1
                
                # Enhanced alert logging
                risk_emoji = "🔴" if confidence > 0.95 else "🟡" if confidence > 0.85 else "🟠"
                logger.warning(f"{risk_emoji} DDoS ALERT: {predicted_label} detected with {confidence:.2f} confidence")
                logger.warning(f"   Source: {flow_data.get('src_ip', 'Unknown')} → Destination: {flow_data.get('dst_ip', 'Unknown')}")
                logger.warning(f"   Duration: {flow_data['duration']:.2f}s, Packets: {flow_data['fwd_packets'] + flow_data['bwd_packets']}")
                logger.warning(f"   Risk Level: {alert['risk_level']}")
                
        except Exception as e:
            logger.error(f"Error in DDoS prediction: {e}")
    
    def start_monitoring(self, interface=None, packet_count=None, duration=None):
        """Enhanced monitoring with better progress reporting"""
        if not self.model_data:
            logger.error("❌ No model loaded. Cannot start monitoring.")
            return
            
        logger.info(f"🔍 Starting optimized DDoS detection")
        logger.info(f"   Interface: {interface or 'default'}")
        logger.info(f"   Confidence threshold: {self.confidence_threshold:.2f}")
        logger.info(f"   Flow timeout: {self.flow_timeout}s")
        logger.info("Press Ctrl+C to stop monitoring")
        
        start_time = time.time()
        
        def packet_handler(pkt):
            self.analyze_packet(pkt)
            
            # Enhanced progress reporting every 1000 packets
            if self.stats['packets_processed'] % 1000 == 0:
                current_time = time.time()
                elapsed = current_time - start_time
                pps = self.stats['packets_processed'] / elapsed if elapsed > 0 else 0
                
                logger.info(f"📊 Progress: {self.stats['packets_processed']:,} packets processed")
                logger.info(f"   Rate: {pps:.1f} packets/sec")
                logger.info(f"   Active flows: {len(self.flows):,}")
                logger.info(f"   Alerts: {self.stats['alerts_generated']:,}")
                logger.info(f"   Filtered: {self.stats['filtered_broadcasts']:,} broadcasts, {self.stats['low_confidence_filtered']:,} low confidence")
            
            # Stop after duration if specified
            if duration and (time.time() - start_time) > duration:
                return True
        
        try:
            sniff(iface=interface, prn=packet_handler, count=packet_count, 
                  stop_filter=lambda x: packet_handler(x) if duration else False)
        except KeyboardInterrupt:
            logger.info("\n⏹️  Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
        
        self.print_enhanced_summary()
    
    def print_enhanced_summary(self):
        """Enhanced summary with detailed statistics"""
        print(f"\n{'='*70}")
        print(f"🎯 OPTIMIZED DDoS DETECTION SUMMARY")
        print(f"{'='*70}")
        
        # Basic statistics
        print(f"📊 Processing Statistics:")
        print(f"   Packets processed: {self.stats['packets_processed']:,}")
        print(f"   Flows analyzed: {len(self.flows):,}")
        print(f"   Total alerts generated: {self.stats['alerts_generated']:,}")
        
        # Classification results
        total_classified = self.stats['benign_flows'] + self.stats['attack_flows']
        if total_classified > 0:
            benign_pct = (self.stats['benign_flows'] / total_classified) * 100
            attack_pct = (self.stats['attack_flows'] / total_classified) * 100
            
            print(f"\n🔍 Classification Results:")
            print(f"   Benign flows: {self.stats['benign_flows']:,} ({benign_pct:.1f}%)")
            print(f"   Attack flows: {self.stats['attack_flows']:,} ({attack_pct:.1f}%)")
        
        # Filtering statistics
        print(f"\n🛡️  Filtering Statistics:")
        print(f"   Broadcast traffic filtered: {self.stats['filtered_broadcasts']:,}")
        print(f"   Low confidence filtered: {self.stats['low_confidence_filtered']:,}")
        print(f"   Confidence threshold: {self.confidence_threshold:.2f}")
        
        # Alert analysis
        if self.alerts:
            print(f"\n🚨 Alert Analysis:")
            
            # Attack type summary
            attack_types = {}
            risk_levels = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for alert in self.alerts:
                attack_type = alert['attack_type']
                risk_level = alert.get('risk_level', 'UNKNOWN')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
            
            print(f"   Attack types detected:")
            for attack_type, count in sorted(attack_types.items()):
                print(f"     {attack_type}: {count} alerts")
            
            print(f"   Risk level distribution:")
            for risk_level, count in risk_levels.items():
                if count > 0:
                    emoji = "🔴" if risk_level == 'HIGH' else "🟡" if risk_level == 'MEDIUM' else "🟠"
                    print(f"     {emoji} {risk_level}: {count} alerts")
            
            # Recent high-confidence alerts
            high_conf_alerts = [a for a in self.alerts if a['confidence'] > 0.9]
            if high_conf_alerts:
                print(f"\n🔴 High Confidence Alerts (>90%):")
                for alert in high_conf_alerts[-3:]:
                    print(f"   {alert['timestamp']}: {alert['attack_type']} "
                          f"(confidence: {alert['confidence']:.2f})")
                    print(f"     {alert['source_ip']} → {alert['destination_ip']}")
        else:
            print(f"\n✅ No attacks detected during monitoring period")
        
        print(f"{'='*70}")
    
    def save_enhanced_alerts(self, filename='enhanced_ddos_alerts.json'):
        """Save alerts with enhanced metadata"""
        alert_data = {
            'monitoring_session': {
                'timestamp': datetime.now().isoformat(),
                'total_packets': self.stats['packets_processed'],
                'total_flows': len(self.flows),
                'confidence_threshold': self.confidence_threshold,
                'flow_timeout': self.flow_timeout
            },
            'statistics': self.stats,
            'alerts': self.alerts
        }
        
        with open(filename, 'w') as f:
            json.dump(alert_data, f, indent=2)
        
        logger.info(f"💾 Enhanced alerts saved to {filename}")

# Enhanced usage function
def main():
    """Main function with configurable parameters"""
    # Initialize detector with higher confidence threshold
    detector = OptimizedDDoSDetector(
        model_path='optimized_ddos_model.pkl',
        confidence_threshold=0.85  # Increased from default to reduce false positives
    )
    
    if detector.model_data:
        # Start monitoring with optimized parameters
        detector.start_monitoring(
            interface='en0',        # Use default interface
            packet_count=50000,    # Process more packets for better analysis
            duration=300           # Monitor for 5 minutes
        )
        
        # Save enhanced alerts
        detector.save_enhanced_alerts('enhanced_ddos_alerts.json')
    else:
        logger.error("Please train the model first by running: python train_ddos_model.py")

if __name__ == "__main__":
    main()
