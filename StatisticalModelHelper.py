
from __future__ import annotations
import numpy as np
from difflib import SequenceMatcher
import pandas as pd



class StatisticalModelHelper:
    """Helper class for statistical calculations and scoring"""
    
    @staticmethod
    def calculate_z_score(value, mean, std):
        """Calculate z-score, handling edge cases"""
        if std == 0 or pd.isna(std):
            return 0.0
        return (value - mean) / std
    
    @staticmethod
    def z_score_to_confidence(z_score, cap_at=5.0):
        """Convert z-score to confidence (0-1), capping extreme values"""
        z_capped = min(abs(z_score), cap_at)
        return z_capped / cap_at
    
    @staticmethod
    def calculate_probability(count, total):
        """Convert frequency to probability with Laplace smoothing"""
        if total == 0:
            return 0.0
        return (count + 1) / (total + 2)
    
    @staticmethod
    def novelty_score(item, baseline_items, threshold=0.85):
        """
        Calculate how novel an item is compared to baseline
        Returns: (is_novel, confidence_score, best_match)
        """
        if not baseline_items:
            return True, 1.0, None
        
        item_lower = str(item).lower().strip()
        max_similarity = 0.0
        best_match = None
        
        for baseline_item in baseline_items:
            baseline_lower = str(baseline_item).lower().strip()
            similarity = SequenceMatcher(None, item_lower, baseline_lower).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
                best_match = baseline_item
        
        is_novel = max_similarity < threshold
        confidence = 1.0 - max_similarity if is_novel else 0.0
        
        return is_novel, confidence, best_match
    
    @staticmethod
    def adaptive_threshold(baseline_items, default=0.85):
        """Calculate adaptive similarity threshold based on baseline diversity"""
        if not baseline_items or len(baseline_items) < 2:
            return default
        
        items_list = list(baseline_items)[:100]
        similarities = []
        
        for i in range(len(items_list)):
            for j in range(i+1, min(i+10, len(items_list))):
                sim = SequenceMatcher(None, 
                                    str(items_list[i]).lower(), 
                                    str(items_list[j]).lower()).ratio()
                similarities.append(sim)
        
        if not similarities:
            return default
        
        median_sim = np.median(similarities)
        adaptive = min(median_sim + 0.15, 0.95)
        return max(adaptive, 0.70)
    
    @staticmethod
    def compare_ip_subnet(ip1, ip2):
        """
        Compare two IPs for subnet similarity
        Returns: (same_subnet, subnet_match_level)
        - subnet_match_level: 0 (no match), 1 (/24 match), 2 (/16 match), 3 (/8 match)
        """
        import ipaddress
        
        try:
            addr1 = ipaddress.ip_address(ip1)
            addr2 = ipaddress.ip_address(ip2)
            
            # Check /24 subnet (e.g., 192.168.1.x)
            net1_24 = ipaddress.ip_network(f"{ip1}/24", strict=False)
            if addr2 in net1_24:
                return True, 1  # Same /24 subnet
            
            # Check /16 subnet (e.g., 192.168.x.x)
            net1_16 = ipaddress.ip_network(f"{ip1}/16", strict=False)
            if addr2 in net1_16:
                return False, 2  # Same /16 subnet
            
            # Check /8 subnet (e.g., 192.x.x.x)
            net1_8 = ipaddress.ip_network(f"{ip1}/8", strict=False)
            if addr2 in net1_8:
                return False, 3  # Same /8 subnet
            
            return False, 0  # Different subnets
        except:
            return False, 0
    
    @staticmethod
    def get_ip_geolocation(ip):
        """
        Get geolocation for IP (country code)
        Returns: country_code or None
        Uses geoip2 if available, otherwise returns None
        """
        try:
            import geoip2.database
            # Try to use MaxMind GeoLite2 database if available
            # User would need to download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
            try:
                reader = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-Country.mmdb')
                response = reader.country(ip)
                return response.country.iso_code
            except:
                # Try alternative path (Windows)
                try:
                    reader = geoip2.database.Reader('C:/GeoIP/GeoLite2-Country.mmdb')
                    response = reader.country(ip)
                    return response.country.iso_code
                except:
                    return None
        except ImportError:
            # geoip2 not installed - use simple heuristic based on IP ranges
            # This is a very basic fallback
            return StatisticalModelHelper._simple_geo_heuristic(ip)
    
    @staticmethod
    def _simple_geo_heuristic(ip):
        """
        Simple geo heuristic when geoip2 is not available
        Returns basic region identifier based on first octet
        """
        try:
            first_octet = int(ip.split('.')[0])
            # Very simplified regional grouping (not accurate, just for relative comparison)
            if first_octet in range(1, 42):
                return "REGION_A"  # Americas-like
            elif first_octet in range(42, 84):
                return "REGION_B"  # Europe-like
            elif first_octet in range(84, 126):
                return "REGION_C"  # Asia-like
            elif first_octet in range(126, 168):
                return "REGION_D"  # Other
            elif first_octet in range(168, 224):
                return "REGION_E"  # Other
            else:
                return "REGION_UNKNOWN"
        except:
            return None
    
    @staticmethod
    def score_new_ip(new_ip, baseline_ips):
        """
        Score a new IP based on subnet and geo-location similarity
        Returns: (severity, confidence, details)
        """
        if not baseline_ips:
            return "HIGH", 0.9, {"reason": "no_baseline_ips"}
        
        # Check subnet matches
        best_subnet_match = 0
        matching_baseline_ip = None
        
        for baseline_ip in baseline_ips:
            same_subnet, match_level = StatisticalModelHelper.compare_ip_subnet(new_ip, baseline_ip)
            if match_level > best_subnet_match:
                best_subnet_match = match_level
                matching_baseline_ip = baseline_ip
        
        # Check geo-location
        new_geo = StatisticalModelHelper.get_ip_geolocation(new_ip)
        same_geo = False
        
        if new_geo and matching_baseline_ip:
            baseline_geo = StatisticalModelHelper.get_ip_geolocation(matching_baseline_ip)
            same_geo = (new_geo == baseline_geo) if baseline_geo else False
        
        # Score based on subnet and geo
        if best_subnet_match == 1:  # Same /24 subnet
            return "LOW", 0.3, {
                "reason": "same_subnet_24",
                "matching_ip": matching_baseline_ip,
                "subnet": "same /24"
            }
        elif best_subnet_match == 2:  # Same /16 subnet
            return "MEDIUM", 0.5, {
                "reason": "same_subnet_16",
                "matching_ip": matching_baseline_ip,
                "subnet": "same /16"
            }
        elif same_geo:  # Same geo, different subnet
            return "MEDIUM", 0.6, {
                "reason": "same_geo_different_subnet",
                "geo": new_geo,
                "matching_ip": matching_baseline_ip
            }
        else:  # Different geo
            return "HIGH", 0.9, {
                "reason": "different_geo",
                "new_geo": new_geo if new_geo else "unknown",
                "baseline_geo_sample": StatisticalModelHelper.get_ip_geolocation(list(baseline_ips)[0]) if baseline_ips else None
            }
    
    @staticmethod
    def calculate_agent_distance(new_key, all_baseline_keys):
        """
        Calculate distance from new agent to existing baselines
        new_key: (machine, process, normalized_args, signer)
        Returns: (confidence, severity, closest_match_info)
        """
        if not all_baseline_keys:
            return 1.0, "LOW", {"reason": "no_baseline_exists"}
        
        new_machine, new_process, new_args, new_signer = new_key
        
        # Find closest matches
        closest_distance = 4  # Max distance (all 4 components different)
        closest_match = None
        match_details = {
            "same_machine_same_process": [],
            "same_process_diff_machine": [],
            "same_machine_diff_process": [],
            "similar_process": []
        }
        
        for baseline_key in all_baseline_keys:
            base_machine, base_process, base_args, base_signer = baseline_key
            distance = 0
            
            # Calculate component-wise distance
            if new_machine != base_machine:
                distance += 1
            if new_process != base_process:
                distance += 1
            else:
                # Track matching processes
                if new_machine == base_machine:
                    match_details["same_machine_same_process"].append({
                        "key": baseline_key,
                        "args_similarity": SequenceMatcher(None, new_args, base_args).ratio()
                    })
                else:
                    match_details["same_process_diff_machine"].append(baseline_key)
            
            if new_args != base_args:
                distance += 1
            if new_signer != base_signer:
                distance += 1
            
            # Track closest match
            if distance < closest_distance:
                closest_distance = distance
                closest_match = baseline_key
            
            # Track similar processes (fuzzy match)
            if new_process != base_process:
                proc_similarity = SequenceMatcher(None, new_process.lower(), base_process.lower()).ratio()
                if proc_similarity > 0.7:
                    match_details["similar_process"].append({
                        "process": base_process,
                        "similarity": proc_similarity
                    })
        
        # Score based on distance and match patterns
        if closest_distance == 0:
            # Exact match (shouldn't happen as this would be in baseline)
            return 0.0, "INFO", {"reason": "exact_match"}
        
        elif closest_distance == 1:
            # One component different
            if match_details["same_machine_same_process"]:
                # Same machine + process, different args or signer
                avg_args_sim = np.mean([m["args_similarity"] for m in match_details["same_machine_same_process"]])
                return 0.4 + (0.3 * (1 - avg_args_sim)), "MEDIUM", {
                    "reason": "same_machine_process_diff_args_or_signer",
                    "distance": 1,
                    "args_similarity": f"{avg_args_sim:.2f}",
                    "closest_match": str(closest_match)
                }
            else:
                return 0.6, "MEDIUM", {
                    "reason": "one_component_different",
                    "distance": 1,
                    "closest_match": str(closest_match)
                }
        
        elif closest_distance == 2:
            # Two components different
            if match_details["same_process_diff_machine"]:
                # Known process on different machine
                return 0.6, "MEDIUM", {
                    "reason": "known_process_different_machine",
                    "distance": 2,
                    "process": new_process,
                    "closest_match": str(closest_match)
                }
            else:
                return 0.75, "HIGH", {
                    "reason": "two_components_different",
                    "distance": 2,
                    "closest_match": str(closest_match)
                }
        
        elif closest_distance == 3:
            # Three components different
            if match_details["similar_process"]:
                # Similar process name exists
                best_similar = max(match_details["similar_process"], key=lambda x: x["similarity"])
                return 0.8, "HIGH", {
                    "reason": "similar_process_exists",
                    "distance": 3,
                    "similar_process": best_similar["process"],
                    "similarity": f"{best_similar['similarity']:.2f}"
                }
            else:
                return 0.9, "HIGH", {
                    "reason": "three_components_different",
                    "distance": 3
                }
        
        else:  # distance == 4
            # Completely different
            return 1.0, "CRITICAL" if not match_details["similar_process"] else "HIGH", {
                "reason": "completely_new_agent",
                "distance": 4,
                "total_baseline_agents": len(all_baseline_keys)
            }
