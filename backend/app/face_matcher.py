import os
import io
import math
import requests
import numpy as np
import cv2
from PIL import Image

def download_image(url, timeout=10):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200 and len(r.content) > 200:
            image = Image.open(io.BytesIO(r.content)).convert('RGB')
            return np.array(image)
    except Exception as e:
        pass
    return None

def compute_phash(img_gray, hash_size=32):
    # Resize to 32x32
    resized = cv2.resize(img_gray, (hash_size, hash_size), interpolation=cv2.INTER_AREA)
    # Compute DCT
    dct = cv2.dct(np.float32(resized))
    # Extract top 8x8 low frequencies (excluding DC term)
    dct_low = dct[:8, :8]
    med = np.median(dct_low)
    diff = dct_low > med
    return diff.flatten()

def hamming_similarity(hash1, hash2):
    dist = np.count_nonzero(hash1 != hash2)
    # 64 bits total
    return max(0.0, 1.0 - (dist / 64.0))

def compute_histogram_similarity(img1_bgr, img2_bgr):
    # Convert to HSV
    hsv1 = cv2.cvtColor(img1_bgr, cv2.COLOR_BGR2HSV)
    hsv2 = cv2.cvtColor(img2_bgr, cv2.COLOR_BGR2HSV)
    
    # Calculate H-S histograms
    hist1 = cv2.calcHist([hsv1], [0, 1], None, [50, 60], [0, 180, 0, 256])
    hist2 = cv2.calcHist([hsv2], [0, 1], None, [50, 60], [0, 180, 0, 256])
    
    cv2.normalize(hist1, hist1, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    cv2.normalize(hist2, hist2, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    
    # Correlation metric (-1 to 1) -> map to 0 to 1
    score = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
    return max(0.0, float(score))

def compute_orb_similarity(gray1, gray2):
    orb = cv2.ORB_create(nfeatures=500)
    kp1, des1 = orb.detectAndCompute(gray1, None)
    kp2, des2 = orb.detectAndCompute(gray2, None)
    
    if des1 is None or des2 is None or len(des1) == 0 or len(des2) == 0:
        return 0.0
    
    # BFMatcher with Hamming distance
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    
    if not matches:
        return 0.0
    
    # Sort matches by distance
    matches = sorted(matches, key=lambda x: x.distance)
    # Good matches have distance < 50
    good_matches = [m for m in matches if m.distance < 50]
    
    ratio = len(good_matches) / max(1, min(len(des1), len(des2)))
    return min(1.0, ratio * 2.0)

def compute_sift_similarity(gray1, gray2):
    sift = cv2.SIFT_create()
    kp1, des1 = sift.detectAndCompute(gray1, None)
    kp2, des2 = sift.detectAndCompute(gray2, None)
    
    if des1 is None or des2 is None or len(des1) < 2 or len(des2) < 2:
        return 0.0
    
    # FLANN or BF matcher with k=2 for Lowe ratio test
    bf = cv2.BFMatcher()
    matches = bf.knnMatch(des1, des2, k=2)
    
    good = []
    for m_n in matches:
        if len(m_n) == 2:
            m, n = m_n
            if m.distance < 0.75 * n.distance:
                good.append(m)
                
    ratio = len(good) / max(1, min(len(des1), len(des2)))
    return min(1.0, ratio * 2.5)

def compare_images(img1_rgb, img2_rgb):
    # Convert RGB to BGR for OpenCV
    bgr1 = cv2.cvtColor(img1_rgb, cv2.COLOR_RGB2BGR)
    bgr2 = cv2.cvtColor(img2_rgb, cv2.COLOR_RGB2BGR)
    
    gray1 = cv2.cvtColor(bgr1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(bgr2, cv2.COLOR_BGR2GRAY)
    
    # 1. Perceptual Hash
    ph1 = compute_phash(gray1)
    ph2 = compute_phash(gray2)
    phash_score = hamming_similarity(ph1, ph2)
    
    # 2. Color Distribution
    color_score = compute_histogram_similarity(bgr1, bgr2)
    
    # 3. Structural Keypoints (SIFT + ORB)
    sift_score = compute_sift_similarity(gray1, gray2)
    orb_score = compute_orb_similarity(gray1, gray2)
    feature_score = max(sift_score, orb_score)
    
    # Weighted composite score
    composite = (phash_score * 0.35) + (feature_score * 0.40) + (color_score * 0.25)
    
    # Confidence level
    percent = round(composite * 100, 1)
    if percent >= 75:
        verdict = "MATCH_HIGH"
    elif percent >= 50:
        verdict = "MATCH_MODERATE"
    else:
        verdict = "NO_MATCH"
        
    return {
        "score_percent": percent,
        "verdict": verdict,
        "details": {
            "phash_similarity": round(phash_score * 100, 1),
            "feature_similarity": round(feature_score * 100, 1),
            "color_similarity": round(color_score * 100, 1)
        }
    }

if __name__ == '__main__':
    # Test on random synthesized face-like arrays
    arr1 = np.zeros((100, 100, 3), dtype=np.uint8)
    cv2.circle(arr1, (50, 50), 30, (200, 180, 150), -1)
    cv2.circle(arr1, (40, 45), 5, (50, 50, 50), -1)
    cv2.circle(arr1, (60, 45), 5, (50, 50, 50), -1)
    
    # Clone and slightly modify
    arr2 = arr1.copy()
    cv2.circle(arr2, (50, 70), 10, (180, 50, 50), -1)
    
    # Completely different image
    arr3 = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
    
    res_same = compare_images(arr1, arr1)
    print("Identical Image comparison:", res_same)
    
    res_mod = compare_images(arr1, arr2)
    print("Modified Image comparison:", res_mod)
    
    res_diff = compare_images(arr1, arr3)
    print("Different Image comparison:", res_diff)
