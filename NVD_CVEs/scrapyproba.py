import scrapy
from scrapy.crawler import CrawlerProcess

class BlogSpider(scrapy.Spider):
    name='ytparser'
    start_urls = ['https://www.youtube.com/results?search_query=ksi']
    
    def parse(self, response):
        all_videos=[]
        dic={}
        
        for video in response.xpath('//div[contains(@class, "yt-lockup yt-lockup-tile yt-lockup-video")]/div[contains(@class, "yt-lockup-dismissable yt-uix-tile")]/div[@class="yt-lockup-content"]'):
            title=video.xpath('h3[@class="yt-lockup-title "]/a/text()').extract()
            dic['title']=''.join(title)
            dur=video.xpath('h3[@class="yt-lockup-title "]/span/text()').extract_first() 
            dic['duration']=dur[13:len(dur)-1]
            dic['channel']=video.xpath('div[@class="yt-lockup-byline "]/a/text()').extract_first()
            meta_info=video.xpath('div[@class="yt-lockup-meta "]/ul[@class="yt-lockup-meta-info"]/li/text()').extract()
            dic['upload_date']=meta_info[0]
            dic['views']=meta_info[1]
            desc=video.xpath('div[@class="yt-lockup-description yt-ui-ellipsis yt-ui-ellipsis-2"]/text()').extract()
            dic['desc']=''.join(desc)
            print dic
            print ''
            dic={}
process = CrawlerProcess({
    'USER_AGENT': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)'
})

process.crawl(BlogSpider)
process.start()

