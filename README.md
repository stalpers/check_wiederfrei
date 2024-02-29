# NewDomains #

Get list of .ch & .li domains that got available recently domains from the Mastodon feed @wiederfrei and check their rank using Alexa Top1000 and Top 10Million Sites$

Download and unzip the data files to the data directory 

Alexa - http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
Top 10 Million - https://www.domcop.com/files/top/top10milliondomains.csv.zip

```
├───data
│   ├───alexa.csv
│   └───top10milliondomains.csv
├───Readme.md
├───LICENSE
└───check_released_domains.py

```

```
python ./check_released_domains.py
```