import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'
import {Link, Redirect} from 'react-router-dom'

const fakeAuth = {
  isAuthenticated: false,
  authenticate(cb) {
    this.isAuthenticated = true
    setTimeout(cb, 100)
  },
  signout(cb) {
    this.isAuthenticated = false
    setTimeout(cb, 100)
  }
}

export default fakeAuth;

class Login extends React.Component {
  state = {
    redirectToReferrer: false
  }
  
  login = () => {
    fakeAuth.authenticate(() => {
      this.setState(() => ({
        redirectToReferrer: true
      }))
    })
  }
  render() {
    const { from } = this.props.location.state || { from: { pathname: '/' } }
    const { redirectToReferrer } = this.state

    if (redirectToReferrer === true) {
      return <Redirect to={from} />
    }

    return (
      <div className={`Root ${Style.Root}`}>
        <h2 className={`title ${Style.Title}`}>You must log in to view the page</h2>
        <button className={`button ${Style.Login}`} onClick={this.login}>Log in</button>
      </div>
    )
  }
}

export {Login, fakeAuth}