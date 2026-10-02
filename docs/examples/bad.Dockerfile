FROM python:latest
ENV SECRET=demonstration-only
USER root
CMD ["python", "--version"]
