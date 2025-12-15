'use client'

import { supabaseClient } from '@/lib/supabase-client'
import { SupabaseAuthClient } from '@supabase/supabase-js/dist/module/lib/SupabaseAuthClient'
import React, { useState } from 'react'


interface Task {
  id: number
  title: string
  description: string
}

export default function Page() {
  const supabase = supabaseClient();  
  const [tasks, setTasks] = useState<Task[]>([])
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [editingId, setEditingId] = useState<number | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!title.trim()) return

    // Add to Supabase
    const { error } = await supabase.from("tasks").insert({ title, description })

    if (error) {
      console.error("Error adding task: ", error.message)
      return
    }

    // Update local state
    if (editingId) {
      setTasks(tasks.map(t =>
        t.id === editingId ? { ...t, title, description } : t
      ))
      setEditingId(null)
    } else {
      const newTask: Task = {
        id: Date.now(),
        title,
        description,
      }
      setTasks([...tasks, newTask])
    }

    setTitle('')
    setDescription('')
  }

  const handleEdit = (task: Task) => {
    setTitle(task.title)
    setDescription(task.description)
    setEditingId(task.id)
  }

  const handleDelete = (id: number) => {
    setTasks(tasks.filter(t => t.id !== id))
  }

  return (
    <div className="min-h-screen bg-neutral-900 text-white flex flex-col items-center justify-center p-6">
      <h1 className="text-2xl font-bold mb-6">Task Manager CRUD</h1>

      {/* Formulário */}
      <form onSubmit={handleSubmit} className="w-full max-w-md">
        <input
          type="text"
          placeholder="Task Title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="w-full mb-2 p-2 rounded bg-neutral-800 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-600"
        />
        <textarea
          placeholder="Task Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="w-full mb-3 p-2 rounded bg-neutral-800 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-600"
        />
        <button
          type="submit"
          className="w-full bg-neutral-700 hover:bg-neutral-600 transition-colors rounded py-2 font-medium"
        >
          {editingId ? 'Update Task' : 'Add Task'}
        </button>
      </form>

      {/* Lista de tarefas */}
      <div className="w-full max-w-md space-y-4 mt-6">
        {tasks.map((task) => (
          <div
            key={task.id}
            className="border border-neutral-700 rounded-lg p-4 text-center shadow-sm"
          >
            <h2 className="font-bold text-lg">{task.title}</h2>
            <p className="text-gray-400 mb-3">{task.description}</p>
            <div className="flex justify-center gap-3">
              <button
                onClick={() => handleEdit(task)}
                className="bg-neutral-700 hover:bg-neutral-600 px-4 py-1 rounded transition-colors text-sm"
              >
                Edit
              </button>
              <button
                onClick={() => handleDelete(task.id)}
                className="bg-neutral-700 hover:bg-neutral-600 px-4 py-1 rounded transition-colors text-sm"
              >
                Delete
              </button>
            </div>
          </div>
        ))}

        {tasks.length === 0 && (
          <div className="text-gray-500 text-center">
            No tasks yet — add your first one above!
          </div>
        )}
      </div>
    </div>
  )
}