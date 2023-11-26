#!/usr/bin/env python
# coding: utf-8

from pyspark import SparkConf
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, when, col
from urllib.parse import urlparse
from pyspark.sql.types import MapType, StringType, IntegerType, DoubleType
from pyspark.ml.feature import VectorAssembler, MinMaxScaler
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.sql.functions import col
from pyspark.sql.types import IntegerType
from pyspark.sql.functions import when
from pyspark.sql import SparkSession
from flask import Flask, request, jsonify
from flask_cors import CORS


conf = SparkConf()
conf.set('spark.jars.packages', 'org.apache.hadoop:hadoop-aws:3.2.2,com.microsoft.azure:spark-mssql-connector_2.12:1.2.0')
conf.set('spark.hadoop.fs.s3a.aws.credentials.provider', 'com.amazonaws.auth.InstanceProfileCredentialsProvider')
spark = SparkSession.builder.config(conf=conf).getOrCreate()

df = spark.read.option('delimiter', ',').option('header', 'true').csv('s3a://tcc-pilha-homol-final-sptech-bucket-homol/pca.csv')
original_df = spark.read.option('delimiter', ',').option('header', 'true').csv('s3a://tcc-pilha-homol-final-sptech-bucket-homol/dataset_phishing.csv')

def extract_features_from_url(url):
    parsed_url = urlparse(url)
    features = {
        "length_url": len(url),
        "length_hostname": len(parsed_url.netloc),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" "),
        "nb_www": url.count("www"),
        "nb_com": url.count("com"),
        "nb_dslash": url.count("//"),
        "http_in_path": int("http" in url),
        "https_token": int("https" in url),
        "ratio_digits_url": sum(c.isdigit() for c in url) / max(len(url), 1),
        "ratio_digits_host": sum(c.isdigit() for c in parsed_url.netloc) / max(len(parsed_url.netloc), 1),
        "punycode": 0,
        "port": int(parsed_url.port != None),
        "tld_in_path": int(parsed_url.netloc.split(".")[-1] in parsed_url.path),
        "tld_in_subdomain": int(parsed_url.netloc.split(".")[-1] in parsed_url.netloc.split(".")[:-1]),
        "abnormal_subdomain": int(len(parsed_url.netloc.split(".")) > 2),
        "nb_subdomains": len(parsed_url.netloc.split(".")),
        "prefix_suffix": int(parsed_url.netloc.startswith("www.") or parsed_url.netloc.endswith(".com")),
        "random_domain": int(parsed_url.netloc.startswith("xn--")),
        "shortening_service": int("bit.ly" in parsed_url.netloc or "goo.gl" in parsed_url.netloc),
        "path_extension": parsed_url.path.endswith((".html", ".php")),
        "nb_redirection": url.count("redir"),
        "nb_external_redirection": url.count("http") - int("http" in url),
        "length_words_raw": len(url.split()),
        "char_repeat": max(url.count(c) for c in set(url)),
        "shortest_words_raw": min(len(w) for w in url.split()),
        "shortest_word_host": min(len(w) for w in parsed_url.netloc.split(".")),
        "shortest_word_path": min(len(w) for w in parsed_url.path.split("/")),
        "longest_words_raw": max(len(w) for w in url.split()),
        "longest_word_host": max(len(w) for w in parsed_url.netloc.split(".")),
        "longest_word_path": max(len(w) for w in parsed_url.path.split("/")),
        "avg_words_raw": len(url.split()) / max(len(parsed_url.netloc.split(".")), 1),
        "avg_word_host": len(parsed_url.netloc.split(".")) / max(len(parsed_url.netloc.split(".")), 1),
        "avg_word_path": len(parsed_url.path.split("/")) / max(len(parsed_url.netloc.split(".")), 1),
        "phish_hints": int("confirm" in url or "account" in url or "secure" in url),
        "domain_in_brand": int("paypal" in url or "ebay" in url),
        "brand_in_subdomain": int("paypal" in parsed_url.netloc or "ebay" in parsed_url.netloc),
        "brand_in_path": int("paypal" in parsed_url.path or "ebay" in parsed_url.path),
        "suspecious_tld": int(parsed_url.netloc.split(".")[-1] in ["zip", "cricket", "link"]),
        "statistical_report": int(".php" in url and "admin" in url),
        "nb_hyperlinks": url.count("<a href"),
        "ratio_intHyperlinks": url.count("<a href") / max(len(url.split()), 1),
        "ratio_extHyperlinks": url.count("<a href=http") / max(url.count("<a href"), 1),
        "ratio_nullHyperlinks": max(url.count("<a href") - url.count("<a href="), 0),
        "nb_extCSS": url.count("<link rel=stylesheet href=http"),
        "ratio_intRedirection": url.count("location.replace") / max(len(url.split()), 1),
        "ratio_extRedirection": url.count("location.replace=http") / max(url.count("location.replace"), 1),
        "ratio_intErrors": url.count("window.status") / max(len(url.split()), 1),
        "ratio_extErrors": url.count("window.status=http") / max(url.count("window.status"), 1),
        "login_form": int("login" in url or "signin" in url),
        "external_favicon": int(".ico" in url),
        "links_in_tags": int("href=" in url),
        "submit_email": int("mailto:" in url),
        "ratio_intMedia": url.count("<img") / max(len(url.split()), 1),
        "ratio_extMedia": url.count("<img src=http") / max(url.count("<img"), 1),
        "sfh": int("about:blank" in url),
        "iframe": int("<iframe" in url),
        "popup_window": int("window.open" in url),
        "safe_anchor": int("<a" in url and 'rel="nofollow"' in url),
        "onmouseover": int("onmouseover=" in url),
        "right_clic": int("event.button==2" in url),
        "empty_title": int('title=""' in url),
        "domain_in_title": int(parsed_url.netloc in url),
        "domain_with_copyright": int("copyright" in url),
        "whois_registered_domain": int("whois" in url),
        "domain_registration_length": int("year" in url),
        "domain_age": int("age" in url),
        "web_traffic": int("traffic" in url),
        "dns_record": int("dns" in url),
        "google_index": int("google" in url),
        "page_rank": int("rank" in url)
    }
    return features

feature_columns = [
    "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and",
    "nb_or", "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash", "nb_star",
    "nb_colon", "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com",
    "nb_dslash", "http_in_path", "https_token", "ratio_digits_url", "ratio_digits_host",
    "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains",
    "prefix_suffix", "random_domain", "shortening_service", "path_extension", "nb_redirection",
    "nb_external_redirection", "length_words_raw", "char_repeat", "shortest_words_raw",
    "shortest_word_host", "shortest_word_path", "longest_words_raw", "longest_word_host",
    "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path", "phish_hints",
    "domain_in_brand", "brand_in_subdomain", "brand_in_path", "suspecious_tld",
    "statistical_report", "nb_hyperlinks", "ratio_intHyperlinks", "ratio_extHyperlinks",
    "ratio_nullHyperlinks", "nb_extCSS", "ratio_intRedirection", "ratio_extRedirection",
    "ratio_intErrors", "ratio_extErrors", "login_form", "external_favicon", "links_in_tags",
    "submit_email", "ratio_intMedia", "ratio_extMedia", "sfh", "iframe", "popup_window",
    "safe_anchor", "onmouseover", "right_clic", "empty_title", "domain_in_title",
    "domain_with_copyright", "whois_registered_domain", "domain_registration_length",
    "domain_age", "web_traffic", "dns_record", "google_index", "page_rank"
]

def extract_final_url_features(url):
    extract_features_udf = udf(extract_features_from_url, MapType(StringType(), IntegerType()))

    url_features_df = spark.createDataFrame([(url,)], ["url"]).withColumn("extracted_features", extract_features_udf(col("url")))

    for col_name in feature_columns:
        url_features_df = url_features_df.withColumn(col_name, col("extracted_features")[col_name])

    url_features_df = url_features_df.na.fill(0)
    
    selected_columns = ["url"] + feature_columns
    final_url_features_df = url_features_df.select(selected_columns)

    return final_url_features_df

data = original_df
data = data.withColumn("status", when(data["status"] == "phishing", 1).otherwise(0))

colunas_desejadas = [
    "url", "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and",
    "nb_or", "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash", "nb_star",
    "nb_colon", "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com",
    "nb_dslash", "http_in_path", "https_token", "ratio_digits_url", "ratio_digits_host",
    "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains",
    "prefix_suffix", "random_domain", "shortening_service", "path_extension", "length_words_raw",
    "char_repeat", "shortest_words_raw", "shortest_word_host", "shortest_word_path", "longest_words_raw",
    "longest_word_host", "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path", "status"
]

data = data.select(colunas_desejadas)

numeric_columns = [
    "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and",
    "nb_or", "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash", "nb_star",
    "nb_colon", "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com",
    "nb_dslash", "http_in_path", "https_token", "ratio_digits_url", "ratio_digits_host",
    "punycode", "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains",
    "prefix_suffix", "random_domain", "shortening_service", "path_extension", "length_words_raw",
    "char_repeat", "shortest_words_raw", "shortest_word_host", "shortest_word_path", "longest_words_raw",
    "longest_word_host", "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path"
]

for column_name in numeric_columns:
    data = data.withColumn(column_name, col(column_name).cast(IntegerType()))

assembler = VectorAssembler(inputCols=numeric_columns, outputCol="features")
data = assembler.transform(data)

scaler = MinMaxScaler(inputCol="features", outputCol="scaled_features")
scaler_model = scaler.fit(data)
data = scaler_model.transform(data)

train_data, test_data = data.randomSplit([0.7, 0.3], seed=42)

rf = RandomForestClassifier(labelCol="status", featuresCol="scaled_features")
model = rf.fit(train_data)

def is_phishing(url):
    new_data = extract_final_url_features(url)

    for column_name in numeric_columns:
        new_data = new_data.withColumn(column_name, col(column_name).cast(IntegerType()))

    new_data = assembler.transform(new_data)

    new_data = scaler_model.transform(new_data)

    prediction = model.transform(new_data).select("prediction").collect()[0]["prediction"]

    if prediction == 1.0:
        return True
    else:
        return False

app = Flask(__name__)
CORS(app, resources={r"/phishing": {"origins": "chrome-extension://ihhoakfhifefdhpmdbkjdmfajoodjmbj"}})

@app.route('/phishing', methods=['POST'])
def api_phishing():
    try:
        if request.method == 'POST':
            data = request.get_json()
            if 'url' in data:
                url = data['url']
                response = jsonify({'is_phishing': is_phishing(url)})
                
                response.headers.add('Access-Control-Allow-Origin', 'chrome-extension://ihhoakfhifefdhpmdbkjdmfajoodjmbj')
                response.headers.add('Access-Control-Allow-Methods', 'POST')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
                
                print(response)
                return response, 201
            else:
                result = f'O campo url não foi encontra no request body {data}'
                print(result)
                return result, 412
        else:
            result = 'Método não permitido'
            print(result)
            return result, 405
    except Exception as e:
        print(str(e))
        return f'Erro ao processar solicitação: {str(e)}', 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)