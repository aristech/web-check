import wappalyzer from 'simple-wappalyzer';
import axios from 'axios';
import middleware from './_common/middleware.js';

const techStackHandler = async (url) => {
  try {
    // Fetch the page HTML and headers
    const response = await axios.get(url, {
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      },
      validateStatus: () => true // Accept any status code
    });

    const html = response.data;
    const headers = response.headers;
    const statusCode = response.status;

    // Analyze with simple-wappalyzer (returns array directly)
    const technologies = await wappalyzer({ url, html, headers, statusCode });

    if (!technologies || technologies.length === 0) {
      throw new Error('Unable to find any technologies for site');
    }

    return { technologies };
  } catch (error) {
    throw new Error(error.message);
  }
};

export const handler = middleware(techStackHandler);
export default handler;
