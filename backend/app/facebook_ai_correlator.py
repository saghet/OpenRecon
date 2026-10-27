import sys
import os
import io
import re
import json
import requests
import numpy as np
import cv2
from PIL import Image

def download_image(url, timeout=8):
    if not url or not url.startswith('http'):
        return None
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200 and len(r.content) > 300:
            image = Image.open(io.BytesIO(r.content)).convert('RGB')
            return np.array(image)
    except Exception:
        pass
    return None

def compute_phash(img_gray, hash_size=32):
    resized = cv2.resize(img_gray, (hash_size, hash_size), interpolation=cv2.INTER_AREA)
    dct = cv2.dct(np.float32(resized))
    dct_low = dct[:8, :8]
    med = np.median(dct_low)
    diff = dct_low > med
    return diff.flatten()

def hamming_similarity(hash1, hash2):
    dist = np.count_nonzero(hash1 != hash2)
    return max(0.0, 1.0 - (dist / 64.0))

def compute_histogram_similarity(img1_bgr, img2_bgr):
    hsv1 = cv2.cvtColor(img1_bgr, cv2.COLOR_BGR2HSV)
    hsv2 = cv2.cvtColor(img2_bgr, cv2.COLOR_BGR2HSV)
    hist1 = cv2.calcHist([hsv1], [0, 1], None, [50, 60], [0, 180, 0, 256])
    hist2 = cv2.calcHist([hsv2], [0, 1], None, [50, 60], [0, 180, 0, 256])
    cv2.normalize(hist1, hist1, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    cv2.normalize(hist2, hist2, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    score = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
    return max(0.0, float(score))

def compute_sift_similarity(gray1, gray2):
    try:
        sift = cv2.SIFT_create()
        kp1, des1 = sift.detectAndCompute(gray1, None)
        kp2, des2 = sift.detectAndCompute(gray2, None)
        if des1 is None or des2 is None or len(des1) < 2 or len(des2) < 2:
            return 0.0
        bf = cv2.BFMatcher()
        matches = bf.knnMatch(des1, des2, k=2)
        good = [m for m, n in matches if len((m, n)) == 2 and m.distance < 0.75 * n.distance]
        ratio = len(good) / max(1, min(len(des1), len(des2)))
        return min(1.0, ratio * 2.5)
    except Exception:
        return 0.0

def compute_orb_similarity(gray1, gray2):
    try:
        orb = cv2.ORB_create(nfeatures=500)
        kp1, des1 = orb.detectAndCompute(gray1, None)
        kp2, des2 = orb.detectAndCompute(gray2, None)
        if des1 is None or des2 is None or len(des1) == 0 or len(des2) == 0:
            return 0.0
        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
        matches = bf.match(des1, des2)
        if not matches:
            return 0.0
        good = [m for m in matches if m.distance < 50]
        ratio = len(good) / max(1, min(len(des1), len(des2)))
        return min(1.0, ratio * 2.0)
    except Exception:
        return 0.0

def compare_images(img1_rgb, img2_rgb):
    bgr1 = cv2.cvtColor(img1_rgb, cv2.COLOR_RGB2BGR)
    bgr2 = cv2.cvtColor(img2_rgb, cv2.COLOR_RGB2BGR)
    gray1 = cv2.cvtColor(bgr1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(bgr2, cv2.COLOR_BGR2GRAY)
    
    ph1 = compute_phash(gray1)
    ph2 = compute_phash(gray2)
    phash_score = float(hamming_similarity(ph1, ph2))
    color_score = float(compute_histogram_similarity(bgr1, bgr2))
    sift_score = float(compute_sift_similarity(gray1, gray2))
    orb_score = float(compute_orb_similarity(gray1, gray2))
    feature_score = max(sift_score, orb_score)
    
    composite = (phash_score * 0.35) + (feature_score * 0.40) + (color_score * 0.25)
    percent = round(float(composite * 100), 1)
    
    if percent >= 75:
        verdict = "MATCH_HIGH"
        confidence = "Coincidencia Alta"
    elif percent >= 50:
        verdict = "MATCH_MODERATE"
        confidence = "Coincidencia Media"
    else:
        verdict = "NO_MATCH"
        confidence = "Baja Similitud Visual"
        
    return {
        "score_percent": percent,
        "verdict": verdict,
        "confidence": confidence,
        "details": {
            "phash_similarity": round(float(phash_score * 100), 1),
            "feature_similarity": round(float(feature_score * 100), 1),
            "color_similarity": round(float(color_score * 100), 1)
        }
    }

def get_fb_meta(slug):
    url = f"https://www.facebook.com/{slug}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1'
    }
    try:
        r = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        if r.status_code == 200:
            og_title = re.findall(r'<meta property="og:title" content="([^"]+)"', r.text)
            og_img = re.findall(r'<meta property="og:image" content="([^"]+)"', r.text)
            if og_title and og_img:
                clean_img = og_img[0].replace('&amp;', '&')
                if 'static.xx.fbcdn.net' not in clean_img and 'rsrc.php' not in clean_img:
                    name = og_title[0].replace(' | Facebook', '').strip()
                    if name.lower() not in ['facebook', 'error', 'iniciar sesión', 'log in']:
                        return {
                            'slug': slug,
                            'url': url,
                            'name': name,
                            'avatar': clean_img
                        }
    except Exception:
        pass
    return None

def generate_candidate_slugs(username, names):
    slugs = []
    if username:
        clean_u = re.sub(r'[^a-zA-Z0-9\._-]', '', username).lower()
        if clean_u:
            slugs.append(clean_u)
    for n in names:
        if not n:
            continue
        clean_name = re.sub(r'\(.*?\)', '', n).strip()
        parts = re.findall(r'[a-zA-Z0-9]+', clean_name.lower())
        if len(parts) >= 2:
            p1, p2 = parts[0], parts[1]
            slugs.extend([
                f"{p1}.{p2}",
                f"{p1}{p2}",
                f"{p1}.{p2}.1",
                f"{p1}.{p2}.2",
                f"{p1}{p2}86",
                f"{p2}.{p1}"
            ])
            if p1 == 'javi':
                slugs.append(f"javier.{p2}")
            elif p1 == 'alex':
                slugs.append(f"alejandro.{p2}")
                slugs.append(f"alexander.{p2}")
            elif p1 == 'samu' or p1 == 'sam':
                slugs.append(f"samuel.{p2}")
    return list(dict.fromkeys(slugs))[:8]

def run_correlation(payload):
    username = payload.get('username', '')
    names = payload.get('names', [])
    source_avatars = payload.get('source_avatars', [])
    
    slugs = generate_candidate_slugs(username, names)
    candidates = []
    
    for s in slugs:
        meta = get_fb_meta(s)
        if meta:
            candidates.append(meta)
            
    matches = []
    
    cached_sources = []
    for s in source_avatars:
        s_url = s.get('url')
        if s_url:
            arr = download_image(s_url)
            if arr is not None:
                cached_sources.append({
                    'platform': s.get('platform', 'Social Media'),
                    'url': s_url,
                    'image': arr
                })
                
    for cand in candidates:
        cand_avatar_url = cand.get('avatar')
        best_match = {
            'profile_url': cand.get('url'),
            'slug': cand.get('slug'),
            'facebook_name': cand.get('name'),
            'facebook_avatar': cand_avatar_url,
            'similarity_percent': 0.0,
            'verdict': 'PROFILE_DISCOVERED',
            'confidence': 'Perfil Encontrado',
            'matched_platform': None,
            'source_avatar_url': None,
            'ai_details': None
        }
        
        if cand_avatar_url and cached_sources:
            cand_arr = download_image(cand_avatar_url)
            if cand_arr is not None:
                for src in cached_sources:
                    cmp_res = compare_images(src['image'], cand_arr)
                    if cmp_res['score_percent'] > best_match['similarity_percent']:
                        best_match['similarity_percent'] = cmp_res['score_percent']
                        best_match['verdict'] = cmp_res['verdict']
                        best_match['confidence'] = cmp_res['confidence']
                        best_match['matched_platform'] = src['platform']
                        best_match['source_avatar_url'] = src['url']
                        best_match['ai_details'] = cmp_res['details']
                        
        matches.append(best_match)
        
    matches = sorted(matches, key=lambda x: x['similarity_percent'], reverse=True)
    
    return {
        'status': 'success',
        'query': {
            'username': username,
            'names': names
        },
        'candidates_count': len(candidates),
        'matches': matches
    }

if __name__ == '__main__':
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        try:
            if os.path.exists(arg):
                with open(arg, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                data = json.loads(arg)
            res = run_correlation(data)
            print(json.dumps(res, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({'status': 'error', 'message': str(e)}))
    else:
        test_payload = {
            'username': 'saghet',
            'names': ['Javi Correa', 'SamuLibre Security Team'],
            'source_avatars': [
                {'platform': 'GitHub', 'url': 'https://avatars.githubusercontent.com/u/102008685?v=4'}
            ]
        }
        print(json.dumps(run_correlation(test_payload), indent=2, ensure_ascii=False))
