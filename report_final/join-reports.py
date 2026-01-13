import glob
import os

# ----------------------------
# Paths
# ----------------------------

# Resolve the directory of this script to construct reliable absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Logical names for the report components involved in the final merge
REPORT_FILES = glob.glob(os.path.join(BASE_DIR, "..", "RESULTS", "*", "alerts_report.md"))
INPUT_REPORT = max(REPORT_FILES, key=os.path.getmtime)
PCAP_NAME = os.path.basename(os.path.dirname(INPUT_REPORT))
RESULT_DIR = os.path.join(BASE_DIR, "..", "RESULTS", PCAP_NAME)

# Absolute paths to the statistics and alerts reports
INPUT_STATS = os.path.join(RESULT_DIR, "stats_report.md")
INPUT_ALERTS = os.path.join(RESULT_DIR, "alerts_report.md")

# Absolute path for the combined final report
OUTPUT_FINAL = os.path.join(RESULT_DIR, "FINAL_REPORT.md")

# ----------------------------
# Writing the final report
# ----------------------------

def read_file(path):
    # Safely read a file if it exists, otherwise return empty content
    if not os.path.exists(path):
        return ""
    with open(path) as f:
        return f.read().strip()

# Load the statistics and alert sections as plain text
stats = read_file(INPUT_STATS)
alerts = read_file(INPUT_ALERTS)

# Create the final report by stitching together the two sections
with open(OUTPUT_FINAL, "w") as out:
    # Write a clear header for the global statistics section
    out.write("""
# ----------------------------------------
# GENERAL STATISTICS
# ----------------------------------------""")
    
    out.write("\n\n")
    out.write(stats)
    out.write("\n\n")
    
    # Write a clear header for the detailed alert section
    out.write("""
# ----------------------------------------
# ALERT DETAILS
# ----------------------------------------""")
    out.write("\n\n")
    out.write(alerts)

# Confirm that the final combined report was written successfully
print(f"[+] Final report written to {OUTPUT_FINAL}")
