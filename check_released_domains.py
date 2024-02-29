import os
import pprint
from collections import namedtuple
import pickle
import logging
import requests
import requests
import csv
from tabulate import tabulate

logging.basicConfig(format='%(asctime)s [%(levelname)s] - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

AlexaDB = namedtuple('AlexaDB', ['rank', 'domain'])
Top10DB = namedtuple('Top10DB', ['rank', 'domain', 'open_rank'])
Top10Results = namedtuple('Top10Results', ['rank', 'open_rank'])


def search_alexa_rank(domain_name, alexa_data: list[AlexaDB]) -> int | None:
    domain_name = domain_name.lower()  # convert to lower case for comparison
    for site in alexa_data:
        if site.domain.lower() == domain_name:  # also convert site.Domain to lower case here
            return site.rank
    return None


def search_top10_rank(domain_name, top10_data: list[Top10DB]) -> Top10Results | None:
    domain_name = domain_name.lower()  # convert to lower case for comparison
    for site in top10_data:
        if site.domain.lower() == domain_name:  # also convert site.Domain to lower case here
            result = Top10Results(rank=site.rank, open_rank=site.open_rank)
            return result
    return None


def read_alexa_data(filename):
    alexa_l = []
    with open(filename, 'r') as file:  # @TODO: check for file exists
        csv_reader = csv.reader(file)
        alexa_l = [AlexaDB(rank=row[0], domain=row[1]) for row in csv_reader]
    return alexa_l


def read_top10_data(filename):
    result = []
    with open(filename, 'r') as file:  # @TODO: check for file exists
        csv_reader = csv.reader(file)
        # Skip the header
        next(csv_reader)
        result = [Top10DB(rank=row[0], domain=row[1], open_rank=row[2]) for row in csv_reader]
    return result


def get_domains():
    contents_list = []
    seen_domains_filename = 'seen_domains.pkl'

    # If file exists, load the seen domains from it
    if os.path.exists(seen_domains_filename):
        with open(seen_domains_filename, 'rb') as seen_domains_file:
            seen_domains = pickle.load(seen_domains_file)
    else:  # Else, create an empty set
        seen_domains = set()

    url = "https://mastodon.social/api/v1/accounts/lookup?&acct=@wiederfrei@botsin.space"
    response = requests.get(url)
    data = response.json()
    id_value = data.get('id')
    url = f"https://mastodon.social/api/v1/accounts/{id_value}/statuses"
    response = requests.get(url)
    data = response.json()
    # Loop through the returned statuses
    not_seen_count = 0
    count = 0
    for status in data:
        # Extract the 'content' field
        content_field = status.get('content')
        content_field = content_field.replace(' sind wieder frei!</p>', '')
        content_field = content_field.replace(' ist wieder frei!</p>', '')
        content_field = content_field.replace('<p>', '').replace(' ', '')
        separated_values = content_field.replace('und', ',').split(',')

        count = count + len(separated_values)
        for value in separated_values:

            if value not in seen_domains:
                contents_list.append(value)
                seen_domains.add(value)
                not_seen_count += 1

        # contents_list.extend(separated_values)
        seen_domains_file = open(seen_domains_filename, 'wb')
        pickle.dump(seen_domains, seen_domains_file)
        seen_domains_file.close()
    logger.info(f'{not_seen_count} New Domains - {count} total downloaded')
    return contents_list


if __name__ == "__main__":
    logger.info("Loading Alexa data")
    alexa = read_alexa_data('data/alexa.csv')
    logger.info("Loading Open Page Rank data")
    top10 = read_top10_data('data/top10milliondomains.csv')
    logger.info("Getting domain information from Mastodon")
    domains = get_domains()

    if len(domains) == 0:
        logger.info("No new domains found ")
    else:
        logger.info("Compiling results")
        result_table=[]
        for domain in domains:
            a = search_alexa_rank(domain_name=domain, alexa_data=alexa)
            t = search_top10_rank(domain_name=domain, top10_data=top10)
            r = 'not available'
            o = 'not available'
            if t is not None:
                r = t.rank
                o = t.open_rank
            result_table.append([domain,a,r,o])
        headers=['Domain','Alexa Rank','Top10M Rank','Open Page Rank']
        print(tabulate(result_table, headers, tablefmt="outline"))
