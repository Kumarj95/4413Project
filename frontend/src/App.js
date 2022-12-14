import React, { Component } from "react";
import { Route, Routes } from "react-router-dom";
import { ToastContainer } from "react-toastify";

import jwtDecode from "jwt-decode";
import Checkout from "./pages/checkout";
import Home from "./pages/home";
import NavBar from "./components/navbar";
import NotFound from "./components/notFound";
import LoginForm from "./pages/loginForm";
import RegisterForm from "./pages/registerForm";
import "react-toastify/dist/ReactToastify.css";
import "bootstrap/dist/css/bootstrap.min.css";
import "./App.css";
import Item from "./pages/item";
import CartProvider from "./components/context/cartContext";

import { getSalesRecords } from "./services/adminService";

import axios from "axios";
import AdminView from "./components/AdminView";

class App extends Component {
    state = {};

    getRefreshToken = async () => {
        const port = window.PORT;
        const apiUrl = `http://localhost:${port}/api/home`;
        axios.defaults.withCredentials = true;
        const response = await axios.post(apiUrl, {
            withCredentials: true,
            credentials: "include",
        });
        // console.log(response.data);
    };

    componentDidMount() {
        this.getRefreshToken();
        // const jwtRefreshcookie = { jwt: jscookie.get("jwt") };
        // console.log("-->" + jwtRefreshcookie.jwt);

        try {
            const accessToken = localStorage.getItem("accToken");
            // console.log(" access token " +accessToken)
            const user = jwtDecode(accessToken).UserInfo;
            this.setState(user);
            // console.log(user);
        } catch (ex) {
            console.log("no access token");
        }

        this.setState({ salesRecords: getSalesRecords() });
    }

    f() {}

    render() {
        return (
            <CartProvider>
                <ToastContainer />
                <NavBar user={this.state} />
                <main className="container">
                    <Routes>
                        <Route exact path="/" element={<Home />} />
                        <Route path="/search" element={<Home />} />
                        <Route path="/admin" element={<AdminView />} />
                        <Route path="/register" element={<RegisterForm />} />
                        <Route path="/login" element={<LoginForm />} />
                        <Route path="/item/:_id" element={<Item />} />
                        <Route path="/not-found" element={<NotFound />} />
                        <Route path="/checkout" element={<Checkout />} />
                        <Route path="/admin" element={<AdminView />} />
                    </Routes>
                </main>
            </CartProvider>
        );
    }
}

export default App;
