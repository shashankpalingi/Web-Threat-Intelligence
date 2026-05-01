import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Scanner from './pages/Scanner'
import History from './pages/History'
import Analytics from './pages/Analytics'
import ModelInfo from './pages/ModelInfo'
import './index.css'

function App() {
  return (
    <Router>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Scanner />} />
            <Route path="/history" element={<History />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/model" element={<ModelInfo />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App
