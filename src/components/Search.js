import React, {useState, useEffect} from 'react';
import { useLocation } from 'react-router-dom';
import './Search.css';


const Search =()=> {
    const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);

  const items = [
    { name: 'Iphone 15 Pro', price: '$1500', image: '/images/image1.jpg' },
    { name: 'Samsung S24 Ultra', price: '$1500', image: '/images/image2.jpg' },
    { name: 'Pixel 8', price: '$600', image: '/images/image3.jpg' },
    { name: 'Xiaomi 13 Pro', price: '$900', image: '/images/image4.jpg' },
  ];

  const useQuery = () => {
    return new URLSearchParams(useLocation().search);
};
const searchQuery = useQuery().get('query');

  useEffect(() => {
    if (searchQuery) {
      setQuery(searchQuery);
      const filteredItems = items.filter(item =>
        item.name.toLowerCase().includes(searchQuery.toLowerCase())
      );
      setResults(filteredItems);
    }
  }, [searchQuery]);

  return (
    <div className="search-container">
      <h1>Search Results</h1>
      <form>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search..."
          />
          <button type="submit">Search</button>
          </form>
          {results.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Price</th>
                  <th>Image</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result) => (
                  <tr key={result.id}> 
                    <td>{result.name}</td>
                    <td>{result.price}</td>
                    <td>
                      <img src={result.image} alt={result.name} className="product-image" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p>Currently not Available</p>
      )}
    </div>
  );
};

export default Search;

    

