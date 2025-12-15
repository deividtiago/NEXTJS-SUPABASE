'use client'

import { useRef } from "react"
import styles from './TicketNew.module.css'

export default function CreateTicket () {
    const ticketTitleRef = useRef(null);
    const ticketDescriptionRef = useRef(null);

    return(
        <article className={styles.article}>
            <h3 className={styles.title}>Create a new ticket</h3>

            <form
                className={styles.form}
                onSubmit={(event) => {
                    event.preventDefault();
                    alert("TODO: Add a new ticket");
            }}
        >
                <input
                    className={styles.input}
                    ref={ticketTitleRef}
                    placeholder="Add a title"
                />
                
                <textarea
                    className={styles.textarea}
                    ref={ticketDescriptionRef}
                    placeholder="Add a comment"
                />

                <button 
                    className={styles.button}
                    type="submit"
                >
                    Create ticket now 
                </button>
            </form>
        </article>
    );
}