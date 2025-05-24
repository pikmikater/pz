import requests
import matplotlib.pyplot as plt

web = "https://bank.gov.ua/NBU_Exchange/exchange_site?start=20250317&end=20250321&valcode=eur&json"
data = requests.get(web)


if data.status_code == 200:
    info = data.json() 

    print("Курс євро:")
    for day in info:
        print(f"Дата: {day['exchangedate']}, Курс: {day['rate']} грн")

  
    days = []
    prices = []
    for day in info:
        days.append(day['exchangedate'])
        prices.append(day['rate'])

   
    plt.figure()  
    plt.plot(days, prices, 'ro-')  
    plt.title("Курс євро за тиждень")
    plt.xlabel("Дні")
    plt.ylabel("Гривні")
    plt.grid() 
    plt.show()

else:
    print(f"ПОМИЛКА! Код: {data.status_code}")
