# vector-search-with-security-logs
The most important item you'll find in this repo is a fairly long Jupyter notebook that shows details and examples around applying AI-driven vector search technology to security log data...specifically, you'll find the following examples:

- Known exploit matching: Matching incoming logs to known malicious logs to raise an alert
- Anomaly detection: Un-matching incoming logs to known benign logs as a means of doing anomaly detection
- Log segmentation: Some clustering exercises done with vector embeddings of the full text logs

All of these is demonstrated with the fabricated log data (which is also checked into the repo) on a tech stack that includes ChromaDB and HuggingFace MiniLM large language models. This is a small amount of data (3 files of 1000 log entries) and minimal footprint techstack, so you should be able to run this demo notebook on a decent laptop or desktop with no issues. To do similar processes with real volumes of this type of data, you'll need a production-grade vector datastore (Databricks with vector indexing, Azure AI Search, well-provisioned Postgres w/ PGvector extension, Qdrant, or similar) would allow the first two items above (exploit matching and anomaly detection) to run effectively.  Some vector databases have support for clustering built-in, so you may be able to do clustering in-database rather than in a notebook (ChromaDB does not, at least not at the moment). That said, I believe this still a decent guide for how to go about these types of exercises.  Feel free to message me with any feedback you might have.

This repo aslo has code for generating the good, malicious, and mixed security logs, as both straight text and as CSV files (similar to what you might extract from Splunk), as well as the log files themselves.
