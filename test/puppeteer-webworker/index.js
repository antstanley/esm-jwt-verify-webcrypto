import puppeteer from 'puppeteer'

const browser = await puppeteer.launch();
const page = await browser.newPage();

const runFunction = async () => {
    page.on('workercreated', worker => {})
}