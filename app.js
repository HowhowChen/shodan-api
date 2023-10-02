if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}
const { encode } = require('url-encode-decode')
const fs = require('fs')
const dayjs = require('dayjs')
const { mainModule } = require('process')

class ShodanAPI {
  constructor(accessToken) {
    this.accessToken = accessToken
  }

  // 發請求獲取服務資訊
  async get(url) {
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          'Content-Type': 'application/json',
        }})

        return response.json()
    } catch (err) {
      console.log(err)
    }
  }

  // Shodan Search API
  async search(servicePattern_Encode, facets = '') {
    try {
      const url = `https://api.shodan.io/shodan/host/search?key=${this.accessToken}&query=${servicePattern_Encode}&facets=${facets}&page=1`
      const result = await this.get(url)
      const dataObject = result
      const defaultCount = 100
      const totalPage = Math.ceil(result.total / defaultCount)

      if (totalPage > 1) {
        for (let page = 2; page <= totalPage; page++) {
          const url = `https://api.shodan.io/shodan/host/search?key=${this.accessToken}&query=${servicePattern_Encode}&facets=${facets}&page=${page}`
          const nextResult = await this.get(url)

          dataObject.matches.push(...nextResult.matches)
          await new Promise(resolve => setTimeout(resolve, 3000)) // sleep
        }
      }

      return dataObject
    } catch (err) {
      console.log(err)
    }
  }

  // 獲取需要的選項
  async searchCustomization(servicePattern_Encode, facets = '') {
    try {
      const result = await this.search(servicePattern_Encode, facets)

      if (result.error) return result.error

      const dataObject = {}
      dataObject.total = result.total

      facets.split(',').forEach(facet => {
        facet = facet.split(':')[0]
        if (facet && result.facets[`${facet}`]) dataObject[`${facet}`] = result.facets[`${facet}`]
      })
      
      // 挑選需要的資訊
      const services = result.matches.map(item => {
        // 彙整CVE
        const cvs = item.vulns ? Object.entries(item.vulns).map(item => {
          delete item[1].references; delete item[1].verified
          return {
            'cve': item[0],
            ...item[1]
          }
        }) : ''

        // 依據_shodan module分類不同服務
        switch (item._shodan.module) {
          case 'https': case 'https-simple-new"':
            return {
              'ip': item.ip_str,
              'country': item.location.country_name,
              'services': [
                {
                  'port': item.port,
                  'service_name': 'HTTP',
                  'extended_service_name': 'HTTPS',
                  ...item.ssl?.chain ? { 'certificate': item.ssl.chain } : {},
                  'transport_protocol': item.transport,
                  ...cvs ? { 'vulns': cvs } : {} 
                }
              ]
            }
          case 'http':
            return {
              'ip': item.ip_str,
              'country': item.location.country_name,
              'services': [
                {
                  'port': item.port,
                  'service_name': 'HTTP',
                  'extended_service_name': 'HTTP',
                  'transport_protocol': item.transport,
                  ...cvs ? { 'vulns': cvs } : {} 
                }
              ]
            }
          default:
            return {
              'ip': item.ip_str,
              'country': item.location.country_name,
              'services': [
                {
                  'port': item.port,
                  'service_name': item._shodan.module,
                  'extended_service_name': item._shodan.module,
                  'transport_protocol': item.transport,
                  ...cvs ? { 'vulns': cvs } : {} 
                }
              ]
            }
        }
      })

      // 客製化重組格式（相同IP的service放一起）
      dataObject.data = []
      services.forEach(service => {
        // 比對是否有資料已在data[]
        if (!dataObject.data.find(({ ip }, index) => {
            if (ip === service.ip) {
              dataObject.data[index].services.push(service.services[0])
              return true
            }
          }) ) dataObject.data.push(service)
      })

      return dataObject
    } catch (err) {
      console.log(err)
    }
  }

  // 建立資料夾
  Makedirs(path, options) {
    if (!fs.existsSync(path)) {
      fs.mkdirSync(path, options)
    }
  }

  // 輸出檔案
  async writeFile(payloads) {
    try {
      this.Makedirs('files', { recursive: true })
      await fs.promises.appendFile(`./files/${dayjs().format('YYYY-MM-DD')}.json`, JSON.stringify(payloads))
    } catch (err) {
      console.log(err)
    }
  }

  //Shodan Facets API
  async facets() {
    try {
      const url = `https://api.shodan.io/shodan/host/search/facets?key=${this.accessToken}`
      const result = await this.get(url)
      
      return { 'facets': result }
    } catch (err) {
      console.log(err)
    }    
  }

  // Shodan Protocols API
  async protocols() {
    try {
      const url = `https://api.shodan.io/shodan/protocols?key=${this.accessToken}`
      const result = await this.get(url)

      return result
    } catch (err) {
      console.log(err)
    }    
  }

  // Shodan MyIP API
  async myIp() {
    try {
      const url = `https://api.shodan.io/tools/myip?key=${this.accessToken}`
      const result = await this.get(url)

      return result
    } catch (err) {
      console.log(err)
    }    
  }

  // Shodan DNS Info
  async dnsInfo(domain) {
    try {
      const url = `https://api.shodan.io/dns/domain/${domain}?key=${this.accessToken}`
      const result = await this.get(url)

      return result
    } catch (err) {
      console.log(err)
    }    
  }

  // Shodan DNS Lookup
  async dnsLookup(domains) {
    try {
      const url = `https://api.shodan.io/dns/resolve?hostnames=${domains}&key=${this.accessToken}`
      const result = await this.get(url)
      
      const data = []
      domains.split(',').forEach(domain => {
        data.push({
          domain,
          ip: result[`${domain}`]
        })
      })

      return data
    } catch (err) {
      console.log(err)
    }    
  }

  // Shodan DNS Reverse Lookup
  async dnsReverseLookup(ips) {
    try {
      const url = `https://api.shodan.io/dns/reverse?ips=${ips}&key=${this.accessToken}`
      const result = await this.get(url)
      
      const data = []
      ips.split(',').forEach(ip => {
        data.push({
          ip,
          domains: result[`${ip}`]
        })
      })

      return data
    } catch (err) {
      console.log(err)
    }
  }

  // Shodan Search Queries API
  async searchQueries(tag) {
    try {
      const url = `https://api.shodan.io/shodan/query/search?query=${tag}&key=${this.accessToken}`
      let result = await this.get(url)
      const defaultLimit = 10 //  each page contains 10 items

      const dataObject = {}
      dataObject.data = result.matches
      dataObject.total = result.total
      if (result.total <= defaultLimit) return dataObject
      
      const pages = Math.ceil(Number(result.total) / defaultLimit)
      for (let page = 2; page <= pages; page++) {
        result = await this.get(`https://api.shodan.io/shodan/query/search?query=${tag}&key=${this.accessToken}&page=${page}`)
        dataObject.data.push(...result.matches)
      }
      
      return dataObject
    } catch (err) {
      console.log(err)
    }
  }
}

async function main() {
  const accessToken = process.env.ACCESS_TOKEN
  const shodanAPI = new ShodanAPI(accessToken)
  
  const servicePattern = ''
  const servicePattern_Encode = encode(servicePattern)
  const facets = '' // e.g. org,country:100
  // shodanAPI.search(servicePattern_Encode, facets)
  shodanAPI.writeFile(await shodanAPI.searchCustomization(servicePattern_Encode, facets))
  
  // const domain = '' // e.g. google.com
  // shodanAPI.dnsInfo(domain)
  
  // const domains = '' // e.g. google.com,facebook.com use Comma-separated list of hostnames
  // shodanAPI.dnsLookup(domains)
  
  // const ips = '' // e.g. 8.8.8.8,1.1.1.1
  // shodanAPI.dnsReverseLookup(ips)
  
  // const tag = '' // e.g. ssh
  // shodanAPI.searchQueries(tag)
}

main()
