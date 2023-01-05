FROM python:3.6

RUN mkdir /app
WORKDIR /app

ADD . /app

RUN pip install gunicorn
RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["gunicorn", "-b", ":5000", "app:app"]