if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}
const { encode } = require('url-encode-decode')
const fs = require('fs')
const dayjs = require('dayjs')

class ShodanAPI {
  constructor(accessToken) {
    this.accessToken = accessToken
  }

  // 發請求獲取服務資訊
  async request(url) {
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
    const url = `https://api.shodan.io/shodan/host/search?key=${this.accessToken}&query=${servicePattern_Encode}&facets=${facets}`
  
    return this.request(url)
  }

  // 獲取需要的選項
  async searchCustomization(servicePattern_Encode, facets = '') {
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
  }

  // 建立資料夾
  Makedirs(path, options) {
    if (!fs.existsSync(path)) {
      fs.mkdirSync(path, options)
    }
  }

  // 輸出檔案
  async writeFile(servicePattern_Encode, facets) {
    this.Makedirs('files', { recursive: true })
    const dataObject = await this.searchCustomization(servicePattern_Encode, facets)
    await fs.promises.appendFile(`./files/${dayjs().format('YYYY-MM-DD')}.json`, JSON.stringify(dataObject))
  }

  //Shodan Facets API
  async facets() {
    const url = `https://api.shodan.io/shodan/host/search/facets?key=${this.accessToken}`
    const result = await this.request(url)
    
    return { 'facets': result }
  }

  // Shodan Protocols API
  async protocols() {
    const url = `https://api.shodan.io/shodan/protocols?key=${this.accessToken}`
    const result = await this.request(url)

    return result
  }
}

const accessToken = process.env.ACCESS_TOKEN
const shodanAPI = new ShodanAPI(accessToken)

const servicePattern = ''
const servicePattern_Encode = encode(servicePattern)
const facets = '' // e.g. org,country:100
shodanAPI.writeFile(servicePattern_Encode, facets)
