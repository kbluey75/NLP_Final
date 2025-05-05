import sys
import os
import json
import traceback
import pandas as pd
import string

from docx import Document
from PyPDF2 import PdfReader
from email import policy
from email.parser import BytesParser

LOG_FILE = "C:/Users/Kaden/Desktop/nlp_script_debug_log.txt"

def safe_log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
    except:
        pass

safe_log("==== Script started ====")

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    safe_log("Loaded spaCy model")
except Exception as e:
    safe_log("Failed to load spaCy model")
    safe_log(str(e))
    safe_log(traceback.format_exc())
    sys.exit(1)

try:
    import inflect
    p = inflect.engine()
except:
    p = None

def clean(text):
    try:
        text = text.lower()
        doc = nlp(text)
        if p:
            text = ' '.join([p.number_to_words(token.text) if token.like_num else token.text for token in doc])
        else:
            text = ' '.join([token.text for token in doc])
        doc = nlp(text)
        text = ' '.join([token.text for token in doc if token.pos_ != "NUM"])
        doc = nlp(text)
        text = ' '.join([word.strip(string.punctuation) for word in text.split()])
        if p:
            text = ' '.join([word for word in text.split() if not p.singular_noun(word)])
        return text
    except Exception as e:
        safe_log("Error in clean(): " + str(e))
        safe_log(traceback.format_exc())
        return ""

def open_document(file_path):
    try:
        safe_log("Opening document: " + file_path)
        if file_path.endswith('.docx'):
            doc = Document(file_path)
            return "\n".join([p.text for p in doc.paragraphs])
        elif file_path.endswith('.txt'):
            with open(file_path, 'r', errors='ignore') as file:
                return file.read()
        elif file_path.endswith('.pdf'):
            pdf_reader = PdfReader(file_path)
            return "\n".join([page.extract_text() or "" for page in pdf_reader.pages])
        elif file_path.endswith('.eml'):
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        return part.get_content()
            return msg.get_content()
        else:
            safe_log("Unsupported file format")
            return ""
    except Exception as e:
        safe_log("Error opening document: " + str(e))
        safe_log(traceback.format_exc())
        return ""

def main(file_path):
    try:
        safe_log("Running NLP on file: " + file_path)

        df1 = pd.read_csv('https://raw.githubusercontent.com/Zoompa919/NLP_Final/refs/heads/main/bad_words.csv', header=None)
        df2 = pd.read_csv('https://raw.githubusercontent.com/Zoompa919/NLP_Final/refs/heads/main/cybersecurity_terms.csv', header=None)
        df = pd.concat([df1, df2], axis=0, ignore_index=True)

        if 402 in df.index:
            df = df.drop(402)

        cleaned_df = [clean(i) for i in df[0] if i]
        df_keywords = list(set(cleaned_df))
        safe_log(f"Loaded and cleaned {len(df_keywords)} keywords")

        doc_text = open_document(file_path)
        if not doc_text:
            return {"status": "error", "message": "Could not read document."}

        clean_doc = clean(doc_text).split()
        matched_terms = [kw for kw in df_keywords if kw in set(clean_doc)]

        safe_log(f"Matched {len(matched_terms)} terms")

        if matched_terms:
            safe_log("Matches: " + ", ".join(matched_terms))
            comment = f"Matched terms: {', '.join(matched_terms)}"
            return {
                "status": "ok",
                "artifacts": [
                    {
                        "name": "Flagged Content",
                        "attributes": {
                            "TSK_NAME": "Keyword Match",
                            "TSK_COMMENT": comment,
                            "TSK_MATCHED_TERMS": ", ".join(matched_terms)
                        }
                    }
                ]
            }
        else:
            safe_log("No matches found.")
            return {
                "status": "ok",
                "artifacts": []
            }

    except Exception as e:
        safe_log("Error in main(): " + str(e))
        safe_log(traceback.format_exc())
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    try:
        file_path = sys.argv[1]
        safe_log(f"=== Called script on file: {file_path} ===")
        result = main(file_path)
        print(json.dumps(result))
    except Exception as e:
        safe_log("Top-level crash:")
        safe_log(str(e))
        safe_log(traceback.format_exc())
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)


