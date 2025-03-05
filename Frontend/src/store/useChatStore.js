import { create } from "zustand";
import toast from "react-hot-toast";
import { axiosInstance } from "../lib/axios";
import { useAuthStore } from "./useAuthStore";

export const useChatStore = create((set,get)=> ({
    messages:[],
    users:[],
    selectedUser:null,
    isUsersLoading:false,
    isMessagesLoading:false,

    getUsers: async()=>{
        set({isUsersLoading:true})
        try {
            const res = await axiosInstance.get(`messages/user`);
            set({users: res.data});
        } catch (error) {
            toast.error(error.response.data.message)
        }finally{
            set({isUsersLoading:false})
        }
    },
    getMessages: async(userID)=>{
        set({isMessagesLoading:true})
        try {
            const res = await axiosInstance.get(`messages/${userID}`);
            set({messages: res.data});
        } catch (error) {
            toast.error(error.response.data.message)
        }finally{
            set({isMessagesLoading:false})
        }
    },
    sendMessage: async(messageData)=>{
        const {messages,selectedUser} = get()
        try {
            const res = await axiosInstance.post(`/messages/send/${selectedUser._id}`,messageData);
            set({messages: [...messages,res.data]})
        } catch (error) {
            toast.error(error.response.data.message)
        }
    },
    
    setSelectedUser: (selectedUser)=>set({selectedUser})
}))