import axios from "axios";
import React from "react";
import { useEffect } from "react";
import { useState, useRef, useContext } from "react";
import { Link, useNavigate } from "react-router-dom";
import { CartContext } from "../components/cartContext";
const Checkout = () => {
    const state = [];
    const cartContext= useContext(CartContext)
    const navigate= useNavigate()
    const port=5000
    const fname = useRef();
    const lname = useRef();
    const email = useRef();
    const address= useRef();
    const address2= useRef();
    const country= useRef();
    const stateref= useRef();
    const zip= useRef();
    const nameCard= useRef();
    const ccnum= useRef();
    const expiration= useRef();
    const ccv= useRef();

    useEffect(()=>{
        const accessToken = localStorage.getItem("accToken");
        if(!accessToken){
            navigate("/login")
            alert("Need to be logged in to do that!")
        }

    },[])

    const userApi=`http://localhost:${port}/api/user`
    const orderApi=`http://localhost:${port}/api/order`

    const handleCheckout= async (e)=>{
        e.preventDefault()
        const res= await axios.get(`${userApi}/getUser`)
        const owner= res.data._id
        console.log(cartContext.items)

        const items= cartContext.items.map((entry)=>{
            return {
                itemId:entry.item._id,
                name:entry.item.name,
                quantity:entry.quantity,
                price:entry.item.price* entry.quantity
            }
        })

        const bill= cartContext.getTotalCost()
        const add= address.current.value+ " "+address2.current.value
        const newOrder={
            owner:owner,
            items:items,
            bill:bill,
            address:address
        }

        const accessResponse=await axios.get(`${userApi}/refresh`)
        const accesToken= accessResponse.data.user
        if(!accesToken){
            alert("Issue with login")
            navigate("/login")
            window.location.reload(false);
        }else{
            localStorage.setItem("accToken", accesToken)
        const body={
            address:add
        }
        const token= localStorage.getItem("accToken")
        const config = {
            headers: { Authorization: `Bearer ${token}` }
        };
        
        await axios.post(`${orderApi}/placeOrder`, body, config)
        
        navigate("/")
        window.location.reload(false);
    }
        

    }
    

    const EmptyCart = () => {
        return (
            <div className="container">
                <div className="row">
                    <div className="col-md-12 py-5 bg-light text-center">
                        <h4 className="p-3 display-5">No item in Cart</h4>
                        <Link to="/" className="btn btn-outline-dark mx-4">
                            <i className="fa fa-arrow-left"></i> Continue
                            Shopping
                        </Link>
                    </div>
                </div>
            </div>
        );
    };

    const ShowCheckout = () => {
        // stale state
        let subtotal = 0;
        let shipping = 30.0;
        let totalItems = 0;

        return (
            <>
                <div className="container py-5">
                    <div className="row my-4">
                        <div className="col-md-5 col-lg-4 order-md-last">
                            <div className="card mb-4">
                                <div className="card-header py-3 bg-light">
                                    <h5 className="mb-0">Order Summary</h5>
                                </div>
                                <div className="card-body">
                                    <ul className="list-group list-group-flush">
                                        <li className="list-group-item d-flex justify-content-between align-items-center border-0 px-0 pb-0">
                                            Products ({totalItems})
                                            <span>${Math.round(subtotal)}</span>
                                        </li>
                                        <li className="list-group-item d-flex justify-content-between align-items-center px-0">
                                            Shipping
                                            <span>${shipping}</span>
                                        </li>
                                        <li className="list-group-item d-flex justify-content-between align-items-center border-0 px-0 mb-3">
                                            <div>
                                                <strong>Total amount</strong>
                                            </div>
                                            <span>
                                                <strong>
                                                    $
                                                    {Math.round(
                                                        subtotal + shipping
                                                    )}
                                                </strong>
                                            </span>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                        <div className="col-md-7 col-lg-8">
                            <div className="card mb-4">
                                <div className="card-header py-3">
                                    <h4 className="mb-0">Billing address</h4>
                                </div>
                                <div className="card-body">
                                    <form
                                        className="needs-validation"
                                        noValidate
                                    >
                                        <div className="row g-3">
                                            <div className="col-sm-6 my-1">
                                                <label
                                                    for="firstName"
                                                    className="form-label"
                                                >
                                                    First name
                                                </label>
                                                <input
                                                ref={fname}
                                                    type="text"
                                                    className="form-control"
                                                    id="firstName"
                                                    placeholder=""
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Valid first name is
                                                    required.
                                                </div>
                                            </div>

                                            <div className="col-sm-6 my-1">
                                                <label
                                                    for="lastName"
                                                    className="form-label"
                                                >
                                                    Last name
                                                </label>
                                                <input
                                                ref={lname}
                                                    type="text"
                                                    className="form-control"
                                                    id="lastName"
                                                    placeholder=""
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Valid last name is required.
                                                </div>
                                            </div>

                                            <div className="col-12 my-1">
                                                <label
                                                    for="email"
                                                    className="form-label"
                                                >
                                                    Email
                                                </label>
                                                <input
                                                ref={email}
                                                    type="email"
                                                    className="form-control"
                                                    id="email"
                                                    placeholder="you@example.com"
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Please enter a valid email
                                                    address for shipping
                                                    updates.
                                                </div>
                                            </div>

                                            <div className="col-12 my-1">
                                                <label
                                                    for="address"
                                                    className="form-label"
                                                >
                                                    Address
                                                </label>
                                                <input
                                                ref={address}
                                                    type="text"
                                                    className="form-control"
                                                    id="address"
                                                    placeholder="1234 Main St"
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Please enter your shipping
                                                    address.
                                                </div>
                                            </div>

                                            <div className="col-12">
                                                <label
                                                    for="address2"
                                                    className="form-label"
                                                >
                                                    Address 2{" "}
                                                    <span className="text-muted">
                                                        (Optional)
                                                    </span>
                                                </label>
                                                <input
                                                ref={address2}
                                                    type="text"
                                                    className="form-control"
                                                    id="address2"
                                                    placeholder="Apartment or suite"
                                                />
                                            </div>

                                            <div className="col-md-5 my-1">
                                                <label
                                                    for="country"
                                                    className="form-label"
                                                >
                                                    Country
                                                </label>
                                                <br />
                                                <select
                                                ref={country}
                                                    className="form-select"
                                                    id="country"
                                                    required
                                                >
                                                    <option value="">
                                                        Choose...
                                                    </option>
                                                    <option>Canada</option>
                                                    <option>USA</option>
                                                    <option>UK</option>
                                                </select>
                                                <div className="invalid-feedback">
                                                    Please select a valid
                                                    country.
                                                </div>
                                            </div>

                                            <div className="col-md-4 my-1">
                                                <label
                                                    for="state"
                                                    className="form-label"
                                                >
                                                    State
                                                </label>
                                                <br />
                                                <select
                                                    className="form-select"
                                                    ref={stateref}
                                                    id="state"
                                                    required
                                                >
                                                    <option value="">
                                                        Choose...
                                                    </option>
                                                    <option>Alberta</option>
                                                    <option>
                                                        British Columbia
                                                    </option>
                                                    <option>Manitoba</option>
                                                    <option>
                                                        New Brunswick
                                                    </option>
                                                    <option>
                                                        Newfoundland and
                                                        Labrador
                                                    </option>
                                                    <option>
                                                        Northwest Territories
                                                    </option>
                                                    <option>Nova Scotia</option>
                                                    <option>Nunavut</option>
                                                    <option>Ontario</option>
                                                    <option>
                                                        Prince Edward Island
                                                    </option>
                                                    <option>Quebec</option>
                                                    <option>
                                                        Saskatchewan
                                                    </option>
                                                    <option>Yukon</option>

                                                    <option>
                                                        Somewhere in US
                                                    </option>
                                                    <option>
                                                        Somewhere in UK
                                                    </option>
                                                </select>
                                                <div className="invalid-feedback">
                                                    Please provide a valid
                                                    state.
                                                </div>
                                            </div>

                                            <div className="col-md-3 my-1">
                                                <label
                                                    for="zip"
                                                    className="form-label"
                                                >
                                                    Zip
                                                </label>
                                                <input
                                                ref={zip}
                                                    type="text"
                                                    className="form-control"
                                                    id="zip"
                                                    placeholder=""
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Zip code required.
                                                </div>
                                            </div>
                                        </div>

                                        <hr className="my-4" />

                                        <h4 className="mb-3">Payment</h4>

                                        <div className="row gy-3">
                                            <div className="col-md-6">
                                                <label
                                                    for="cc-name"
                                                    className="form-label"
                                                >
                                                    Name on card
                                                </label>
                                                <input
                                                ref={nameCard}
                                                    type="text"
                                                    className="form-control"
                                                    id="cc-name"
                                                    placeholder=""
                                                    required
                                                />
                                                <small className="text-muted">
                                                    Full name as displayed on
                                                    card
                                                </small>
                                                <div className="invalid-feedback">
                                                    Name on card is required
                                                </div>
                                            </div>

                                            <div className="col-md-6">
                                                <label
                                                    for="cc-number"
                                                    className="form-label"
                                                >
                                                    Credit card number
                                                </label>
                                                <input
                                                ref={ccnum}
                                                    type="text"
                                                    className="form-control"
                                                    id="cc-number"
                                                    placeholder=""
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Credit card number is
                                                    required
                                                </div>
                                            </div>

                                            <div className="col-md-3">
                                                <label
                                                    for="cc-expiration"
                                                    className="form-label"
                                                >
                                                    Expiration
                                                </label>
                                                <input
                                                ref={expiration}
                                                    type="text"
                                                    className="form-control"
                                                    id="cc-expiration"
                                                    placeholder=""
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Expiration date required
                                                </div>
                                            </div>

                                            <div className="col-md-3">
                                                <label
                                                    for="cc-cvv"
                                                    className="form-label"
                                                >
                                                    CVV
                                                </label>
                                                <input
                                                ref={ccv}
                                                    type="text"
                                                    className="form-control"
                                                    id="cc-cvv"
                                                    placeholder=""
                                                    required
                                                />
                                                <div className="invalid-feedback">
                                                    Security code required
                                                </div>
                                            </div>
                                        </div>

                                        <hr className="my-4" />

                                        <button
                                            className="w-100 btn btn-primary "
                                            type="submit"
                                            onClick={handleCheckout}
                                        >
                                            Continue to checkout
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </>
        );
    };
    return (

        <>
        {/* {user? */}
            <div className="container my-3 py-3">
                <h1 className="text-center">Checkout</h1>
                <hr />
                {state.length + 1 ? <ShowCheckout /> : <EmptyCart />}
            </div>
            {/* :<>{alert("Please Login To Checkout!")}
            <Navigate to="/login"/>  */}
            {/* </>} */}
        </>
    );
};

export default Checkout;
